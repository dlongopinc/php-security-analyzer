<?php
// public/index.php

// IMPORTANT: Run 'composer install' in the project root directory to create this autoloader.
require __DIR__ . '/vendor/autoload.php';

use Dlongopinc\SecurityAnalyzer\SecurityAnalyzer;

$projectPath = __DIR__;
$analyzer = new SecurityAnalyzer();
$files = $analyzer->analyzePhpFiles($projectPath);

$found = false;
$totalIssues = 0;
$fileCount = 0;
$analyzedFiles = count($files);

$fileIssues = [];
foreach ($files as $file) {
    $issues = $analyzer->checkFile($file);
    if (!empty($issues)) {
        $found = true;
        $totalIssues += count($issues);
        $fileCount++;
        $fileIssues[$file] = $issues;
    }
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Input Security Analyzer</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.10.5/font/bootstrap-icons.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
        }

        .main-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
        }

        .file-card {
            border-left: 5px solid #dc3545;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }

        .success-card {
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            color: white;
            border: none;
            box-shadow: 0 4px 15px rgba(76, 175, 80, 0.3);
        }

        .stats-card {
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%);
            color: white;
            border: none;
            box-shadow: 0 4px 15px rgba(33, 150, 243, 0.3);
        }

        .code-block {
            background: #f8f9fa;
            border-left: 4px solid #dc3545;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }

        .fix-block {
            background: #d4edda;
            border-left: 4px solid #28a745;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }

        .copy-btn {
            transition: all 0.3s ease;
        }

        .copy-btn:hover {
            transform: scale(1.05);
        }

        .table-hover tbody tr:hover {
            background-color: rgba(33, 150, 243, 0.1);
        }

        .badge-line {
            background: linear-gradient(45deg, #FF6B6B, #4ECDC4);
        }

        .badge-var {
            background: linear-gradient(45deg, #dc3545, #fd7e14);
        }

        .vulnerability-icon {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% {
                opacity: 1;
            }

            50% {
                opacity: 0.7;
            }

            100% {
                opacity: 1;
            }
        }

        .navbar-brand {
            font-weight: bold;
            font-size: 1.5rem;
        }

        .progress-bar {
            background: linear-gradient(45deg, #667eea, #764ba2);
        }

        .issue-count {
            background: linear-gradient(45deg, #ff6b6b, #ee5a52);
        }
    </style>
</head>

<body>
    <div class="container-fluid py-4">
        <div class="row mb-4">
            <div class="col-12">
                <div class="main-header p-4 text-center">
                    <h1 class="display-5 fw-bold mb-3">
                        <i class="bi bi-shield-exclamation vulnerability-icon"></i> PHP Input Security Analyzer
                    </h1>
                    <p class="lead mb-0">
                        <i class="bi bi-folder2-open"></i> Analyzed folder: <strong><?= htmlspecialchars($projectPath) ?></strong>
                    </p>
                </div>
            </div>
        </div>

        <?php if (!$found) : ?>
            <div class="row">
                <div class="col-12">
                    <div class="card success-card">
                        <div class="card-body text-center py-5">
                            <i class="bi bi-check-circle-fill" style="font-size: 4rem; margin-bottom: 1rem;"></i>
                            <h2 class="card-title">🎉 All Inputs are Secure!</h2>
                            <p class="card-text lead">
                                No use of variables without htmlspecialchars() was found in **<?= $analyzedFiles ?>** analyzed files.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        <?php else : ?>
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card stats-card">
                        <div class="card-header">
                            <h3 class="card-title mb-0"><i class="bi bi-graph-up"></i> Analysis Summary</h3>
                        </div>
                        <div class="card-body">
                            <div class="row text-center">
                                <div class="col-md-3">
                                    <div class="d-flex flex-column"><span class="display-6 fw-bold"><?= $fileCount ?></span><small class="text-light">Vulnerable Files</small></div>
                                </div>
                                <div class="col-md-3">
                                    <div class="d-flex flex-column"><span class="display-6 fw-bold"><?= $totalIssues ?></span><small class="text-light">Total Issues</small></div>
                                </div>
                                <div class="col-md-3">
                                    <div class="d-flex flex-column"><span class="display-6 fw-bold"><?= $analyzedFiles ?></span><small class="text-light">Files Analyzed</small></div>
                                </div>
                                <div class="col-md-3">
                                    <div class="d-flex flex-column"><span class="display-6 fw-bold"><?= ($analyzedFiles > 0) ? round(($fileCount / $analyzedFiles) * 100) : 0 ?>%</span><small class="text-light">Risk Level</small></div>
                                </div>
                            </div>
                            <div class="mt-4">
                                <div class="d-flex justify-content-between align-items-center mb-2"><span>Analysis Progress</span><span>100%</span></div>
                                <div class="progress" style="height: 8px;">
                                    <div class="progress-bar" role="progressbar" style="width: 100%"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <?php foreach ($fileIssues as $file => $issues) : ?>
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card file-card">
                            <div class="card-header bg-danger text-white">
                                <div class="d-flex justify-content-between align-items-center">
                                    <h4 class="card-title mb-0"><i class="bi bi-file-code-fill"></i> <?= htmlspecialchars(basename($file)) ?></h4>
                                    <span class="badge issue-count fs-6"><?= count($issues) ?> issues</span>
                                </div>
                                <small class="d-block mt-1 opacity-75"><i class="bi bi-folder"></i> <?= htmlspecialchars($file) ?></small>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table mb-0">
                                        <thead class="table-dark">
                                            <tr>
                                                <th scope="col" width="80"><i class="bi bi-hash"></i> Line</th>
                                                <th scope="col" width="120"><i class="bi bi-code-slash"></i> Variable</th>
                                                <th scope="col" width="40%"><i class="bi bi-exclamation-triangle"></i> Vulnerable Code</th>
                                                <th scope="col" width="40%"><i class="bi bi-check-circle"></i> Suggested Fix</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($issues as $issue) : ?>
                                                <tr>
                                                    <td><span class="badge badge-line text-white fs-6"><?= $issue['line'] ?></span></td>
                                                    <td><code class="badge badge-var text-white fs-6">$<?= htmlspecialchars($issue['var']) ?></code></td>
                                                    <td>
                                                        <div class="code-block p-3 rounded"><code><?= htmlspecialchars($issue['code']) ?></code></div>
                                                    </td>
                                                    <td>
                                                        <div class="fix-block p-3 rounded position-relative"><code id="fix_<?= md5($file . $issue['line'] . $issue['var']) ?>"><?= htmlspecialchars($issue['fix']) ?></code><button class="btn btn-success btn-sm copy-btn position-absolute top-0 end-0 m-2" onclick="copyToClipboard('fix_<?= md5($file . $issue['line'] . $issue['var']) ?>')" data-bs-toggle="tooltip" data-bs-placement="top" title="Copy fix code"><i class="bi bi-clipboard"></i></button></div>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
            <div class="row">
                <div class="col-12">
                    <div class="alert alert-info" role="alert">
                        <h4 class="alert-heading"><i class="bi bi-info-circle-fill"></i> Important Information</h4>
                        <p class="mb-0">This analyzer detects the use of user input variables that are not secured with <code>htmlspecialchars()</code>. This can lead to **Cross-Site Scripting (XSS)** vulnerabilities.</p>
                        <hr>
                        <p class="mb-0"><i class="bi bi-lightbulb-fill"></i> **Tip:** Always use <code>htmlspecialchars()</code> when displaying user input data to the browser to prevent XSS attacks.</p>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });

        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            const text = element.textContent || element.innerText;
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => showCopySuccess(element), err => fallbackCopyTextToClipboard(text, element));
            } else {
                fallbackCopyTextToClipboard(text, element);
            }
        }

        function fallbackCopyTextToClipboard(text, element) {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.top = "0";
            textArea.style.left = "0";
            textArea.style.position = "fixed";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                if (document.execCommand('copy')) showCopySuccess(element);
            } catch (err) {
                console.error('Fallback: Oops, unable to copy', err);
            }
            document.body.removeChild(textArea);
        }

        function showCopySuccess(element) {
            const button = element.parentNode.querySelector('.copy-btn');
            const originalHTML = button.innerHTML;
            button.innerHTML = '<i class="bi bi-check"></i> Copied!';
            button.classList.remove('btn-success');
            button.classList.add('btn-info');
            showToast('Code successfully copied to clipboard!', 'success');
            setTimeout(() => {
                button.innerHTML = originalHTML;
                button.classList.remove('btn-info');
                button.classList.add('btn-success');
            }, 2000);
        }

        function showToast(message, type = 'info') {
            let toastContainer = document.querySelector('.toast-container');
            if (!toastContainer) {
                toastContainer = document.createElement('div');
                toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
                document.body.appendChild(toastContainer);
            }
            const toastId = 'toast-' + Date.now();
            const toastHTML = `<div id="${toastId}" class="toast align-items-center text-bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true"><div class="d-flex"><div class="toast-body"><i class="bi bi-check-circle-fill me-2"></i>${message}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>`;
            toastContainer.insertAdjacentHTML('beforeend', toastHTML);
            const toastElement = document.getElementById(toastId);
            const toast = new bootstrap.Toast(toastElement, {
                autohide: true,
                delay: 3000
            });
            toast.show();
            toastElement.addEventListener('hidden.bs.toast', () => {
                toastElement.remove();
            });
        }
    </script>
</body>

</html>