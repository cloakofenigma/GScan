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
                        resume: Optional[bool] = None):
        """Main Git scan functionality.

        When called with no arguments the parameters are gathered interactively;
        when arguments are supplied (non-interactive/CLI mode) prompts are skipped.
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

