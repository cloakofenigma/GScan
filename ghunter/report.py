"""HTML report generation."""
import json
import html
import os
from datetime import datetime
from pathlib import Path
from colorama import Fore, Style

class ReportMixin:
    """Report generation mixed into GHunter."""

    def generate_html_report(self, results_file: str):
        """Generate professional HTML report"""
        if not os.path.exists(results_file):
            print(f"{Fore.RED}Error: Results file '{results_file}' not found!{Style.RESET_ALL}")
            return

        # Load findings
        findings = []
        with open(results_file, 'r') as f:
            for line in f:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if not findings:
            print(f"{Fore.RED}No findings to report!{Style.RESET_ALL}")
            return

        # Generate HTML
        output_dir = Path(results_file).parent
        report_file = output_dir / "report.html"

        # Count statistics
        total = len(findings)
        verified = sum(1 for f in findings if f.get('verified'))
        false_positives = sum(1 for f in findings if f.get('false_positive'))
        needs_review = sum(1 for f in findings if f.get('needs_review'))
        critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high = sum(1 for f in findings if f.get('severity') == 'HIGH')
        medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        low = sum(1 for f in findings if f.get('severity') == 'LOW')
        # Tool-specific statistics
        by_trufflehog = sum(1 for f in findings if 'trufflehog' in f.get('found_by', [f.get('scan_tool', '')]))
        by_gitleaks = sum(1 for f in findings if 'gitleaks' in f.get('found_by', [f.get('scan_tool', '')]))
        by_both_tools = sum(1 for f in findings if len(f.get('found_by', [])) > 1)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>G-Hunter Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}

        header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}

        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
        }}

        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}

        .stat-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }}

        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}

        .controls {{
            padding: 20px 30px;
            background: white;
            border-bottom: 1px solid #ddd;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}

        .search-box {{
            flex: 1;
            min-width: 250px;
        }}

        .search-box input {{
            width: 100%;
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }}

        .filter-group {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 8px 16px;
            border: 1px solid #ddd;
            background: white;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 14px;
        }}

        .filter-btn:hover {{
            background: #f8f9fa;
        }}

        .filter-btn.active {{
            background: #007bff;
            color: white;
            border-color: #007bff;
        }}

        .findings {{
            padding: 30px;
        }}

        .finding-card {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}

        .finding-card:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}

        .finding-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}

        .finding-title {{
            font-weight: bold;
            font-size: 1.1em;
        }}

        .finding-badges {{
            display: flex;
            gap: 10px;
        }}

        .badge {{
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }}

        .badge-verified {{
            background: #28a745;
            color: white;
        }}

        .badge-unverified {{
            background: #6c757d;
            color: white;
        }}

        .badge-false-positive {{
            background: #ffc107;
            color: #333;
        }}

        .badge-needs-review {{
            background: #fd7e14;
            color: white;
        }}

        .badge-severity {{
            color: white;
        }}

        .badge-severity.critical {{ background: #dc3545; }}
        .badge-severity.high {{ background: #fd7e14; }}
        .badge-severity.medium {{ background: #ffc107; color: #333; }}
        .badge-severity.low {{ background: #28a745; }}

        .badge-tool {{
            font-size: 0.75em;
            padding: 3px 8px;
        }}
        .badge-trufflehog {{ background: #6f42c1; color: white; }}
        .badge-gitleaks {{ background: #20c997; color: white; }}
        .badge-both {{ background: #17a2b8; color: white; }}

        .finding-body {{
            padding: 20px;
            display: none;
        }}

        .finding-body.expanded {{
            display: block;
        }}

        .finding-detail {{
            margin-bottom: 15px;
        }}

        .finding-detail-label {{
            font-weight: bold;
            color: #666;
            margin-bottom: 5px;
        }}

        .finding-detail-value {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }}

        .ai-analysis {{
            background: #e7f3ff;
            border-left: 4px solid #007bff;
            padding: 15px;
            margin-top: 15px;
            border-radius: 5px;
        }}

        .ai-analysis-title {{
            font-weight: bold;
            color: #007bff;
            margin-bottom: 10px;
        }}

        footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
        }}

        .no-results {{
            text-align: center;
            padding: 40px;
            color: #666;
            font-size: 1.2em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 G-Hunter Security Report</h1>
            <p>GitHub Secrets & Sensitive Information Analysis</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{total}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Verified</div>
                <div class="stat-value" style="color: #28a745;">{verified}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label critical">Critical</div>
                <div class="stat-value critical">{critical}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label high">High</div>
                <div class="stat-value high">{high}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label medium">Medium</div>
                <div class="stat-value medium">{medium}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label low">Low</div>
                <div class="stat-value low">{low}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">False Positives</div>
                <div class="stat-value" style="color: #ffc107;">{false_positives}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Needs Review</div>
                <div class="stat-value" style="color: #fd7e14;">{needs_review}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" style="color: #6f42c1;">TruffleHog</div>
                <div class="stat-value" style="color: #6f42c1;">{by_trufflehog}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" style="color: #20c997;">Gitleaks</div>
                <div class="stat-value" style="color: #20c997;">{by_gitleaks}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" style="color: #17a2b8;">Found by Both</div>
                <div class="stat-value" style="color: #17a2b8;">{by_both_tools}</div>
            </div>
        </div>

        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="🔍 Search findings..." onkeyup="filterFindings()">
            </div>
            <div class="filter-group">
                <button class="filter-btn active" onclick="filterBySeverity('all')">All</button>
                <button class="filter-btn" onclick="filterBySeverity('CRITICAL')">Critical</button>
                <button class="filter-btn" onclick="filterBySeverity('HIGH')">High</button>
                <button class="filter-btn" onclick="filterBySeverity('MEDIUM')">Medium</button>
                <button class="filter-btn" onclick="filterBySeverity('LOW')">Low</button>
            </div>
            <div class="filter-group">
                <button class="filter-btn" onclick="filterByType('verified')">Verified Only</button>
                <button class="filter-btn" onclick="filterByType('false_positive')">Hide False Positives</button>
                <button class="filter-btn" onclick="filterByType('needs_review')">Needs Review</button>
            </div>
            <div class="filter-group">
                <button class="filter-btn active" onclick="filterByTool('all')" id="tool-all">All Tools</button>
                <button class="filter-btn" onclick="filterByTool('trufflehog')" id="tool-trufflehog" style="border-color: #6f42c1;">TruffleHog</button>
                <button class="filter-btn" onclick="filterByTool('gitleaks')" id="tool-gitleaks" style="border-color: #20c997;">Gitleaks</button>
                <button class="filter-btn" onclick="filterByTool('both')" id="tool-both" style="border-color: #17a2b8;">Both Tools</button>
            </div>
        </div>

        <div class="findings" id="findingsContainer">
"""

        # Add finding cards
        for idx, finding in enumerate(findings):
            # All values below originate from scanned repos / secret contents and
            # are attacker-influenced, so escape every field before embedding it
            # in HTML to prevent stored XSS in the report.
            severity_raw = str(finding.get('severity', 'UNKNOWN'))
            severity = html.escape(severity_raw.lower(), quote=True)
            severity_text = html.escape(severity_raw)
            verified_badge = 'badge-verified' if finding.get('verified') else 'badge-unverified'
            verified_text = 'Verified' if finding.get('verified') else 'Unverified'

            detector_name = html.escape(str(finding.get('detector_name', 'Unknown Detector')))
            detector_type = html.escape(str(finding.get('detector_type', 'Unknown Type')))
            file_path = html.escape(str(finding.get('file_path', 'N/A')))
            commit = html.escape(str(finding.get('commit', 'N/A')))
            timestamp = html.escape(str(finding.get('timestamp', 'N/A')))

            # Only allow http(s) links; everything else (e.g. javascript:) -> '#'
            repo_url_raw = finding.get('repo_url', '')
            if isinstance(repo_url_raw, str) and repo_url_raw.startswith(('https://', 'http://')):
                repo_url_href = html.escape(repo_url_raw, quote=True)
            else:
                repo_url_href = '#'
            repo_url_text = html.escape(str(repo_url_raw) if repo_url_raw else 'N/A')

            # Determine scan tool for badge and filtering
            found_by = finding.get('found_by', [])
            scan_tool = finding.get('scan_tool', '')
            if len(found_by) > 1:
                tool_class = 'badge-both'
                tool_text = 'Both'
                tool_data = 'both'
            elif 'trufflehog' in found_by or scan_tool == 'trufflehog':
                tool_class = 'badge-trufflehog'
                tool_text = 'TruffleHog'
                tool_data = 'trufflehog'
            elif 'gitleaks' in found_by or scan_tool == 'gitleaks':
                tool_class = 'badge-gitleaks'
                tool_text = 'Gitleaks'
                tool_data = 'gitleaks'
            else:
                tool_class = 'badge-tool'
                tool_text = 'Unknown'
                tool_data = 'unknown'

            badges_html = f'<span class="badge badge-tool {tool_class}">{tool_text}</span>'
            badges_html += f'<span class="badge {verified_badge}">{verified_text}</span>'
            badges_html += f'<span class="badge badge-severity {severity}">{severity_text}</span>'

            if finding.get('false_positive'):
                badges_html += '<span class="badge badge-false-positive">False Positive</span>'

            if finding.get('needs_review'):
                badges_html += '<span class="badge badge-needs-review">Needs Review</span>'

            ai_analysis_html = ""
            if finding.get('ai_analysis'):
                ai = finding['ai_analysis']
                ai_analysis_html = f"""
                <div class="ai-analysis">
                    <div class="ai-analysis-title">🤖 AI Analysis</div>
                    <p><strong>Assessment:</strong> {html.escape(str(ai.get('reason', 'N/A')))}</p>
                </div>
                """

            html_content += f"""
            <div class="finding-card" data-severity="{severity}" data-verified="{str(finding.get('verified')).lower()}"
                 data-false-positive="{str(finding.get('false_positive')).lower()}"
                 data-needs-review="{str(finding.get('needs_review')).lower()}"
                 data-tool="{tool_data}">
                <div class="finding-header" onclick="toggleFinding({idx})">
                    <div class="finding-title">
                        {detector_name} - {detector_type}
                    </div>
                    <div class="finding-badges">
                        {badges_html}
                    </div>
                </div>
                <div class="finding-body" id="finding-{idx}">
                    <div class="finding-detail">
                        <div class="finding-detail-label">Repository</div>
                        <div class="finding-detail-value">
                            <a href="{repo_url_href}" target="_blank" rel="noopener noreferrer">{repo_url_text}</a>
                        </div>
                    </div>
                    <div class="finding-detail">
                        <div class="finding-detail-label">File Path</div>
                        <div class="finding-detail-value">{file_path}</div>
                    </div>
                    <div class="finding-detail">
                        <div class="finding-detail-label">Commit</div>
                        <div class="finding-detail-value">{commit}</div>
                    </div>
                    <div class="finding-detail">
                        <div class="finding-detail-label">Timestamp</div>
                        <div class="finding-detail-value">{timestamp}</div>
                    </div>
                    {ai_analysis_html}
                </div>
            </div>
            """

        html_content += """
        </div>

        <footer>
            <p>Generated by <strong>G-Hunter v3.0</strong> - Professional GitHub Secrets Scanner</p>
            <p style="margin-top: 10px; font-size: 0.9em;">⚠️ Handle this report securely - contains sensitive security information</p>
        </footer>
    </div>

    <script>
        let currentSeverityFilter = 'all';
        let currentTypeFilter = null;
        let currentToolFilter = 'all';

        function toggleFinding(id) {
            const body = document.getElementById('finding-' + id);
            body.classList.toggle('expanded');
        }

        function filterBySeverity(severity) {
            currentSeverityFilter = severity;

            // Update button states for severity
            document.querySelectorAll('.filter-group:nth-child(2) .filter-btn').forEach(btn => {
                if (btn.textContent.toLowerCase() === severity.toLowerCase() ||
                    (btn.textContent === 'All' && severity === 'all')) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });

            applyFilters();
        }

        function filterByType(type) {
            // Toggle type filter
            if (currentTypeFilter === type) {
                currentTypeFilter = null;
            } else {
                currentTypeFilter = type;
            }

            applyFilters();
        }

        function filterByTool(tool) {
            currentToolFilter = tool;

            // Update button states for tool filter
            ['all', 'trufflehog', 'gitleaks', 'both'].forEach(t => {
                const btn = document.getElementById('tool-' + t);
                if (btn) {
                    if (t === tool) {
                        btn.classList.add('active');
                    } else {
                        btn.classList.remove('active');
                    }
                }
            });

            applyFilters();
        }

        function filterFindings() {
            applyFilters();
        }

        function applyFilters() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            let visibleCount = 0;

            cards.forEach(card => {
                let show = true;

                // Severity filter
                if (currentSeverityFilter !== 'all') {
                    show = show && card.dataset.severity === currentSeverityFilter.toLowerCase();
                }

                // Type filter
                if (currentTypeFilter === 'verified') {
                    show = show && card.dataset.verified === 'true';
                } else if (currentTypeFilter === 'false_positive') {
                    show = show && card.dataset.falsePositive !== 'true';
                } else if (currentTypeFilter === 'needs_review') {
                    show = show && card.dataset.needsReview === 'true';
                }

                // Tool filter
                if (currentToolFilter !== 'all') {
                    show = show && card.dataset.tool === currentToolFilter;
                }

                // Search filter
                if (searchTerm) {
                    const text = card.textContent.toLowerCase();
                    show = show && text.includes(searchTerm);
                }

                card.style.display = show ? 'block' : 'none';
                if (show) visibleCount++;
            });

            // Show "no results" message if needed
            const container = document.getElementById('findingsContainer');
            let noResults = container.querySelector('.no-results');

            if (visibleCount === 0) {
                if (!noResults) {
                    noResults = document.createElement('div');
                    noResults.className = 'no-results';
                    noResults.textContent = 'No findings match the current filters';
                    container.appendChild(noResults);
                }
            } else if (noResults) {
                noResults.remove();
            }
        }
    </script>
</body>
</html>
"""

        # Write HTML file
        with open(report_file, 'w') as f:
            f.write(html_content)

        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║              HTML Report Generated Successfully!            ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"Report saved to: {report_file}")
        print(f"\nOpen in browser: file://{report_file.absolute()}\n")

    async def generate_report_menu(self):
        """Generate HTML report menu"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║           Generate HTML Report                              ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        results_file = input(f"{Fore.GREEN}Enter path to scan results JSON file:{Style.RESET_ALL} ").strip()

        if not os.path.exists(results_file):
            print(f"{Fore.RED}Error: Results file '{results_file}' not found!{Style.RESET_ALL}")
            return

        self.generate_html_report(results_file)

