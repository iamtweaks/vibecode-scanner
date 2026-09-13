import { Octokit } from '@octokit/rest'
import { scanContent } from './rules'
import { parseGitHubUrl } from '@/lib/validation'
import { scanKnownCves, type PackageFile } from './known-cves'
import type { GitHubScanResult, Finding, SeverityCounts } from '@/lib/types'

// ============== Constants ==============

// File extensions to scan
const CODE_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.go', '.java', '.cs', '.php',
  '.html', '.css', '.scss', '.json', '.yaml', '.yml',
  '.sh', '.bash', '.sql', '.md'
]

// Directories to skip during scanning
const SKIP_DIRS = [
  'node_modules', '.git', 'dist', 'build', 'coverage',
  '.next', '__pycache__', 'vendor', '.venv', 'target',
  'bin', 'obj', '.cache', '.parcel-cache'
]

// Maximum files to scan (prevent abuse)
const MAX_FILES_TO_SCAN = 500

// Maximum file size to scan (1MB)
const MAX_FILE_SIZE = 1_000_000

// ============== Utility Functions ==============

/**
 * Initialize severity counts
 */
function initSeverityCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
}

/**
 * Filter files to scan based on extensions and directories to skip
 */
function filterScannableFiles(tree: Array<{ path: string; type: string }>): string[] {
  return tree
    .filter((item) => 
      item.type === 'blob' && 
      CODE_EXTENSIONS.some(ext => item.path.endsWith(ext)) &&
      !SKIP_DIRS.some(dir => item.path.includes(dir))
    )
    .slice(0, MAX_FILES_TO_SCAN)
    .map(item => item.path)
}

/**
 * Calculate severity counts from findings
 */
function calculateSeverityCounts(findings: Finding[]): SeverityCounts {
  const counts = initSeverityCounts()
  for (const f of findings) {
    if (f.severity in counts) {
      counts[f.severity]++
    }
  }
  return counts
}

// ============== Core Functions ==============

/**
 * Fetch repository file tree
 */
async function fetchRepoTree(
  octokit: Octokit,
  owner: string,
  repo: string,
  branch?: string
): Promise<string[]> {
  try {
    const { data } = await octokit.rest.repos.get({
      owner,
      repo,
      ref: branch,
    })
    
    const targetBranch = branch || (data as any).default_branch || 'main'
    
    const treeResponse = await octokit.rest.git.getTree({
      owner,
      repo,
      tree_sha: targetBranch,
      recursive: 'true',
    })
    
    return filterScannableFiles((treeResponse.data.tree as any[]))
  } catch (error) {
    console.error('Error fetching repo tree:', error)
    return []
  }
}

/**
 * Fetch content of a single file
 */
async function fetchFileContent(
  octokit: Octokit,
  owner: string,
  repo: string,
  path: string,
  branch?: string
): Promise<string | null> {
  try {
    const { data } = await octokit.rest.repos.getContent({
      owner,
      repo,
      path,
      ref: branch,
    }) as any
    
    if (data.encoding === 'base64') {
      const content = Buffer.from(data.content, 'base64').toString('utf-8')
      // Skip files that are too large
      if (content.length > MAX_FILE_SIZE) {
        console.warn(`Skipping ${path} - file too large (>1MB)`)
        return null
      }
      return content
    }
    return null
  } catch {
    return null
  }
}

/**
 * Check if repository exists and is accessible
 */
async function checkRepoAccess(
  octokit: Octokit,
  owner: string,
  repo: string
): Promise<{ accessible: boolean; isPrivate: boolean; error?: string }> {
  try {
    const { data } = await octokit.rest.repos.get({ owner, repo })
    return { accessible: true, isPrivate: Boolean((data as any).private) }
  } catch (error: any) {
    if (error.status === 404) {
      return { accessible: false, isPrivate: false, error: 'Repository not found. Make sure it\'s public.' }
    }
    if (error.status === 403) {
      return { accessible: false, isPrivate: true, error: 'Repository is private. Public repos only.' }
    }
    return { accessible: false, isPrivate: false, error: 'Could not access repository.' }
  }
}

// ============== Main Scanner Function ==============

export async function scanGitHubRepo(
  url: string,
  githubToken?: string
): Promise<GitHubScanResult> {
  const startTime = Date.now()
  
  // Parse GitHub URL
  const parsed = parseGitHubUrl(url)
  if (!parsed.isValid) {
    throw new Error('Invalid GitHub URL. Use format: https://github.com/owner/repo')
  }
  
  const { owner, repo, branch } = parsed
  
  // Initialize Octokit with optional auth
  const octokit = new Octokit({
    auth: githubToken,
  })
  
  // Check repo access
  const accessCheck = await checkRepoAccess(octokit, owner, repo)
  if (!accessCheck.accessible) {
    throw new Error(accessCheck.error || 'Could not access repository')
  }
  
  // Fetch file tree
  const files = await fetchRepoTree(octokit, owner, repo, branch)
  
  if (files.length === 0) {
    return {
      findings: [],
      severityCounts: initSeverityCounts(),
      scannedFiles: 0,
      scanDuration: Date.now() - startTime,
    }
  }
  
  // Scan files
  const findings: Finding[] = []
  // Track every package.json we touch so we can run the Known-CVE pass
  // after the per-file content scan finishes.
  const packageFiles: PackageFile[] = []

  for (const filePath of files) {
    const content = await fetchFileContent(octokit, owner, repo, filePath, branch)
    if (content) {
      const fileFindings = scanContent(content, filePath)
      findings.push(...fileFindings)
      // Collect package.json contents — Known CVE scan needs the raw
      // JSON, not the parsed AST, because the scanner re-parses locally
      // (different package.json grammar assumptions = a footgun).
      if (/package\.json$/i.test(filePath)) {
        packageFiles.push({ filePath, content })
      }
    }
  }

  // Wire the Known CVE scanner in here, AFTER every package.json is
  // collected. Failures inside scanKnownCves are best-effort and never
  // abort the overall scan.
  try {
    const cveFindings = await scanKnownCves(packageFiles, process.env)
    findings.push(...cveFindings)
  } catch (err) {
    console.warn('Known CVE scan failed (continuing):', (err as Error).message)
  }

  return {
    findings,
    severityCounts: calculateSeverityCounts(findings),
    scannedFiles: files.length,
    scanDuration: Date.now() - startTime,
  }
}
