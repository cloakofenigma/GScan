"""GitHub code-search client and the git-dork scan."""
import asyncio
import os
import time
import aiohttp
from pathlib import Path
from typing import List, Set, Tuple, Optional
from tqdm import tqdm
from colorama import Fore, Style
from .models import ScanProgress

class SearchMixin:
    """GitHub search + git_scan mixed into GHunter."""

    async def create_session(self):
        """Create async HTTP session"""
        headers = {
            "Authorization": f"token {self.config.github_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "G-Hunter/3.0"
        }
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(headers=headers, timeout=timeout)
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent)

    async def close_session(self):
        """Close async HTTP session"""
        if self.session and not self.session.closed:
            await self.session.close()
            await asyncio.sleep(0.1)

    def _rate_limit_wait(self, response) -> int:
        """Compute how long to back off on a 403/429 using GitHub headers."""
        # Retry-After (seconds) is used for secondary/abuse rate limits
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return max(1, int(retry_after))
            except ValueError:
                pass
        # Fall back to X-RateLimit-Reset (epoch seconds) when the budget is spent
        reset = response.headers.get("X-RateLimit-Reset")
        remaining = response.headers.get("X-RateLimit-Remaining")
        if reset and remaining == "0":
            try:
                wait = int(reset) - int(time.time())
                if wait > 0:
                    return min(wait + 1, 120)
            except ValueError:
                pass
        return 60

    async def _get_page(self, url: str, params: dict) -> Tuple[Optional[list], Optional[int]]:
        """Fetch one page from a GitHub REST/search endpoint with retry + backoff.

        Returns (items, status). `items` is None only on a hard failure (so the
        caller stops paging). Search endpoints wrap results in {"items": [...]};
        list endpoints return a bare array — both are normalized to a list.
        """
        for attempt in range(self.config.retry_attempts):
            try:
                async with self.session.get(url, params=params) as response:
                    status = response.status
                    if status == 200:
                        data = await response.json()
                        if isinstance(data, dict):
                            items = data.get("items", [])
                        else:
                            items = data
                        return (items if isinstance(items, list) else []), 200
                    if status in (403, 429):
                        wait = self._rate_limit_wait(response)
                        self.logger.warning(f"Rate limit on {url}, waiting {wait}s...")
                        await asyncio.sleep(wait)
                        continue
                    if status in (404, 422):
                        return [], status
                    self.logger.error(f"HTTP {status} for {url}")
                    return None, status
            except Exception as e:
                self.logger.error(f"Attempt {attempt + 1} failed for {url}: {e}")
                if attempt < self.config.retry_attempts - 1:
                    await asyncio.sleep(2 ** attempt)
        return None, None

    async def _paginate(self, url: str, params: dict) -> Tuple[list, Optional[int]]:
        """Collect items across pages from a GitHub endpoint (up to max_pages).

        Returns (items, first_page_status). The status lets callers distinguish
        e.g. a 404 owner from an empty-but-valid result set.
        """
        per_page = 100
        results: list = []
        first_status = None

        for page in range(1, self.config.max_pages + 1):
            if self.shutdown_event.is_set():
                break
            items, status = await self._get_page(
                url, {**params, "per_page": per_page, "page": page}
            )
            if page == 1:
                first_status = status
            if items is None:
                break
            results.extend(items)
            if len(items) < per_page:
                break
            await asyncio.sleep(60 / self.config.rate_limit)

        return results, first_status

    @staticmethod
    def _as_git_url(url: Optional[str]) -> Optional[str]:
        """Normalize a repo/gist URL to a clone-ready .git URL."""
        if not url:
            return None
        return url if url.endswith(".git") else url + ".git"

    async def enumerate_owner_repos(self, owner: str) -> Set[str]:
        """List every repository for an org or user (bypasses the 1000 cap).

        Tries the org endpoint first, then the user endpoint, so the caller need
        not know which kind of owner it is.
        """
        repos: Set[str] = set()
        for kind, type_param in (("orgs", "all"), ("users", "owner")):
            items, status = await self._paginate(
                f"https://api.github.com/{kind}/{owner}/repos", {"type": type_param}
            )
            if status == 404:
                continue  # not this kind of owner; try the next
            for item in items:
                git_url = self._as_git_url(item.get("clone_url") or item.get("html_url"))
                if git_url:
                    repos.add(git_url)
            break  # first non-404 owner kind wins
        return repos

    async def enumerate_user_gists(self, user: str) -> Set[str]:
        """List a user's public gists as clone-ready git URLs."""
        gists: Set[str] = set()
        items, _ = await self._paginate(
            f"https://api.github.com/users/{user}/gists", {}
        )
        for item in items:
            git_url = self._as_git_url(item.get("git_pull_url"))
            if git_url:
                gists.add(git_url)
        return gists

    async def search_commits(self, keyword: str, dork: str = "") -> Tuple[Set[str], Set[str]]:
        """Search commit messages/content (a source code search misses).

        Returns (repo_git_urls, commit_urls).
        """
        repos, urls = set(), set()
        query = f"{keyword} {dork}".strip()
        items, _ = await self._paginate(
            "https://api.github.com/search/commits", {"q": query}
        )
        for item in items:
            repo_html = (item.get("repository") or {}).get("html_url")
            git_url = self._as_git_url(repo_html)
            if git_url:
                repos.add(git_url)
            commit_url = item.get("html_url")
            if commit_url:
                urls.add(commit_url)
        return repos, urls

    # Non-overlapping file-size buckets (bytes) used to partition a query that
    # saturates the 1000-result cap. Together they cover all file sizes, so the
    # union is complete; sets dedup any overlap with the base query.
    _SIZE_BUCKETS = [(None, 999), (1000, 4999), (5000, 19999), (20000, 99999), (100000, None)]

    @staticmethod
    def _size_q(low, high) -> str:
        """Build a GitHub `size:` qualifier for a (low, high) byte range."""
        if low is None:
            return f"size:<{high + 1}"
        if high is None:
            return f"size:>={low}"
        return f"size:{low}..{high}"

    async def _search_pages(self, query: str) -> Tuple[Set[str], Set[str], bool]:
        """Page through one query. Returns (repos, urls, capped).

        `capped` is True when the query exhausted the allowed page range with a
        full final page — i.e. it likely hit the API's 1000-result ceiling and
        more results exist than we can reach without partitioning.
        """
        repos, urls = set(), set()
        per_page = 100
        capped = False

        for page in range(1, self.config.max_pages + 1):
            if self.shutdown_event.is_set():
                break

            page_items = None  # None = page could not be fetched

            for attempt in range(self.config.retry_attempts):
                try:
                    params = {"q": query, "per_page": per_page, "page": page}

                    async with self.session.get(self.config.base_url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            page_items = data.get("items", [])
                            break

                        elif response.status in (403, 429):
                            wait = self._rate_limit_wait(response)
                            self.logger.warning(f"Rate limit hit for '{query}', waiting {wait}s...")
                            await asyncio.sleep(wait)
                            continue

                        elif response.status == 422:
                            # Invalid query, or paging past the 1000-result cap
                            self.logger.debug(f"422 for '{query}' page {page} (end of results)")
                            page_items = []
                            break

                        else:
                            self.logger.error(f"HTTP {response.status} for '{query}'")

                except Exception as e:
                    self.logger.error(f"Attempt {attempt + 1} failed for '{query}': {e}")
                    if attempt < self.config.retry_attempts - 1:
                        await asyncio.sleep(2 ** attempt)
                    else:
                        self.progress.errors += 1

            # Could not fetch this page after all retries -> stop paging
            if page_items is None:
                break

            for item in page_items:
                repo_url = item["repository"]["html_url"]
                file_url = item["html_url"]

                # Append .git suffix for clone compatibility
                if not repo_url.endswith(".git"):
                    repo_url = repo_url + ".git"
                repos.add(repo_url)

                # Check file extension
                if any(file_url.lower().endswith(ext) for ext in self.config.valid_extensions):
                    urls.add(file_url)

            # Last page reached (short or empty page)
            if len(page_items) < per_page:
                break

            # A full page on the final allowed page => results were truncated
            if page == self.config.max_pages:
                capped = True

            # Throttle between pages of the same query
            await asyncio.sleep(60 / self.config.rate_limit)

        return repos, urls, capped

    async def _search_with_splitting(self, base_query: str, ranges, depth: int) -> Tuple[Set[str], Set[str]]:
        """Run base_query across the given size ranges, subdividing any range
        that is itself capped (down to max_split_depth)."""
        repos, urls = set(), set()
        for low, high in ranges:
            if self.shutdown_event.is_set():
                break

            sub_query = f"{base_query} {self._size_q(low, high)}"
            r, u, capped = await self._search_pages(sub_query)
            repos |= r
            urls |= u

            if not capped:
                continue

            # Still capped: subdivide a finite range one level deeper if allowed
            if depth < self.config.max_split_depth and low is not None and high is not None and high - low >= 2:
                mid = (low + high) // 2
                deeper = await self._search_with_splitting(
                    base_query, [(low, mid), (mid + 1, high)], depth + 1
                )
                repos |= deeper[0]
                urls |= deeper[1]
            else:
                self.logger.warning(f"Query still capped after size split: '{sub_query}'")

        return repos, urls

    async def search_github(self, keyword: str, dork: str) -> Tuple[Set[str], Set[str]]:
        """Search GitHub with retry, pagination, and size-based query splitting.

        The code-search API returns at most 100 results per page and 1000 total.
        When a query saturates that cap, we re-run it partitioned by file size so
        each sub-query gets its own 1000 ceiling, recovering results that the cap
        would otherwise hide.
        """
        async with self.semaphore:
            base_query = f"{keyword} {dork}"
            repos, urls, capped = await self._search_pages(base_query)

            # Only split when capped, splitting is enabled, and the query doesn't
            # already constrain size (which would conflict with our qualifier).
            if capped and self.config.split_on_cap and "size:" not in base_query.lower():
                self.logger.info(f"Query hit 1000-result cap, splitting by size: '{base_query}'")
                sr, su = await self._search_with_splitting(base_query, self._SIZE_BUCKETS, 0)
                repos |= sr
                urls |= su

            # Throttle between queries
            await asyncio.sleep(60 / self.config.rate_limit)
            return repos, urls

    async def git_scan(self, keywords: Optional[List[str]] = None,
                        dorks_file: Optional[str] = None,
                        resume: Optional[bool] = None,
                        include_commits: bool = False):
        """Main Git scan functionality.

        When called with no arguments the parameters are gathered interactively;
        when arguments are supplied (non-interactive/CLI mode) prompts are skipped.
        With include_commits=True, each query also searches commit history.
        """
        interactive = keywords is None
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║            Git Scan - GitHub Dorking Search                 ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        # Keywords
        if keywords is None:
            keywords_input = input(f"{Fore.GREEN}Enter keywords (comma-separated):{Style.RESET_ALL} ").strip()
            keywords = [k.strip() for k in keywords_input.split(",") if k.strip()]
        if not keywords:
            print(f"{Fore.RED}Error: No keywords provided!{Style.RESET_ALL}")
            return

        # Dorks file
        if dorks_file is None:
            dorks_file = input(f"{Fore.GREEN}Enter path to git dorks file (default: gitDorks.txt):{Style.RESET_ALL} ").strip()
        if not dorks_file:
            dorks_file = "gitDorks.txt"

        if not os.path.exists(dorks_file):
            print(f"{Fore.RED}Error: Dorks file '{dorks_file}' not found!{Style.RESET_ALL}")
            return

        # Load dorks
        dorks = self.load_dorks(dorks_file)
        if not dorks:
            print(f"{Fore.RED}No dorks loaded!{Style.RESET_ALL}")
            return

        # Create output directory
        first_keyword = keywords[0].replace("/", "_").replace("\\", "_")
        output_dir = self.config.output_base_dir / first_keyword
        output_dir.mkdir(parents=True, exist_ok=True)

        # Resume handling
        progress_file = output_dir / "progress.json"
        if resume is None:
            resume = False
            if progress_file.exists() and interactive:
                resume_input = input(f"{Fore.YELLOW}Previous scan found. Resume? (y/n):{Style.RESET_ALL} ").strip().lower()
                resume = resume_input == 'y'

        # Load or create progress
        if resume:
            self.progress = self.load_progress(output_dir)
            print(f"{Fore.GREEN}Resuming scan... ({self.progress.completed_queries}/{self.progress.total_queries} completed){Style.RESET_ALL}")
        else:
            self.progress = ScanProgress()
            self.progress.total_queries = len(keywords) * len(dorks)
            self.progress.start_time = time.time()

        # Output files
        repos_file_path = output_dir / "repos.txt"
        urls_file_path = output_dir / "urls.txt"

        # Open files in append mode
        repos_file_mode = 'a' if resume else 'w'
        urls_file_mode = 'a' if resume else 'w'

        print(f"\n{Fore.YELLOW}Starting scan...{Style.RESET_ALL}")
        print(f"Keywords: {', '.join(keywords)}")
        print(f"Dorks: {len(dorks)} loaded")
        print(f"Output directory: {output_dir}\n")

        self._audit("git_scan_start", output_dir, keywords=keywords,
                    dork_count=len(dorks), include_commits=include_commits,
                    resume=bool(resume))

        await self.create_session()

        try:
            with open(repos_file_path, repos_file_mode) as repos_file, \
                 open(urls_file_path, urls_file_mode) as urls_file:

                with tqdm(total=self.progress.total_queries,
                         initial=self.progress.completed_queries,
                         desc="Scanning",
                         bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]') as pbar:

                    for keyword in keywords:
                        for dork in dorks:
                            if self.shutdown_event.is_set():
                                break

                            query = f"{keyword}:::{dork}"

                            # Skip if already completed
                            if query in self.progress.completed_queries_set:
                                continue

                            repos, urls = await self.search_github(keyword, dork)

                            # Optionally augment with commit-search results
                            if include_commits:
                                c_repos, c_urls = await self.search_commits(keyword, dork)
                                repos |= c_repos
                                urls |= c_urls

                            # Write new results
                            for repo in repos:
                                if repo not in self.progress.completed_repos:
                                    repos_file.write(f"{repo}\n")
                                    repos_file.flush()
                                    self.progress.completed_repos.add(repo)
                                    self.progress.repos_found += 1

                            for url in urls:
                                if url not in self.progress.completed_urls:
                                    urls_file.write(f"{url}\n")
                                    urls_file.flush()
                                    self.progress.completed_urls.add(url)
                                    self.progress.urls_found += 1

                            # Mark query as completed
                            self.progress.completed_queries_set.add(query)
                            self.progress.completed_queries += 1

                            # Save progress
                            self.save_progress(output_dir)

                            pbar.update(1)
                            pbar.set_postfix({
                                'Repos': self.progress.repos_found,
                                'URLs': self.progress.urls_found,
                                'Errors': self.progress.errors
                            })

                        if self.shutdown_event.is_set():
                            break

        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            self.progress.errors += 1

        finally:
            await self.close_session()

        # Display results
        elapsed_time = time.time() - self.progress.start_time
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    Scan Completed!                          ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Repositories found: {self.progress.repos_found}")
        print(f"File URLs found: {self.progress.urls_found}")
        print(f"Errors: {self.progress.errors}")
        print(f"\nResults saved to: {output_dir}/")
        print(f"  • {repos_file_path}")
        print(f"  • {urls_file_path}\n")

        self._audit("git_scan_complete", output_dir,
                    repos_found=self.progress.repos_found,
                    urls_found=self.progress.urls_found,
                    errors=self.progress.errors,
                    elapsed_seconds=round(elapsed_time, 2))

    async def enum_scan(self, owner: Optional[str] = None,
                        include_gists: bool = True):
        """Enumerate every repo (and optionally gist) for an org/user.

        This bypasses the code-search 1000-result cap entirely by listing repos
        directly. Output is a repos.txt that feeds straight into `repo` scan.
        """
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║          Enumerate - Org/User Repositories & Gists          ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        if owner is None:
            owner = input(f"{Fore.GREEN}Enter GitHub org or username:{Style.RESET_ALL} ").strip()
        if not owner:
            print(f"{Fore.RED}Error: No owner provided!{Style.RESET_ALL}")
            return

        safe_owner = owner.replace("/", "_").replace("\\", "_")
        output_dir = self.config.output_base_dir / safe_owner
        output_dir.mkdir(parents=True, exist_ok=True)
        repos_file_path = output_dir / "repos.txt"

        print(f"{Fore.YELLOW}Enumerating '{owner}'...{Style.RESET_ALL}")
        await self.create_session()
        try:
            repos = await self.enumerate_owner_repos(owner)
            gists = await self.enumerate_user_gists(owner) if include_gists else set()
        finally:
            await self.close_session()

        all_repos = repos | gists
        if not all_repos:
            print(f"{Fore.RED}No repositories or gists found for '{owner}'.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}(Check the name, or the account may have no public repos.){Style.RESET_ALL}\n")
            return

        with open(repos_file_path, "w") as f:
            for repo in sorted(all_repos):
                f.write(f"{repo}\n")

        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                  Enumeration Completed!                     ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"Repositories: {len(repos)}")
        if include_gists:
            print(f"Gists: {len(gists)}")
        print(f"Total (deduplicated): {len(all_repos)}")
        print(f"\nSaved to: {repos_file_path}")
        print(f"\n{Fore.CYAN}Next:{Style.RESET_ALL} python ghunter_pro.py repo -f {repos_file_path} -t both\n")

        self._audit("enum_complete", output_dir, owner=owner,
                    repos=len(repos), gists=len(gists), total=len(all_repos))

