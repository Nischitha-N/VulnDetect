import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? 'http://localhost:8000',
  timeout: 60_000,
})

/**
 * Upload a file (or zip) for scanning.
 * Returns ScanResponse JSON.
 */
export async function scanFile(file, onUploadProgress) {
  const fd = new FormData()
  fd.append('file', file)
  const { data } = await api.post('/api/v1/scan', fd, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress,
  })
  return data
}

/**
 * Fetch a past scan by ID.
 */
export async function getScan(scanId) {
  const { data } = await api.get(`/api/v1/scan/${scanId}`)
  return data
}

/**
 * List recent scans (no results, summaries only).
 */
export async function listScans(limit = 20) {
  const { data } = await api.get('/api/v1/scans', { params: { limit } })
  return data.scans
}

/**
 * Backend health check.
 */
export async function healthCheck() {
  try {
    const { data } = await api.get('/api/v1/health', { timeout: 2500 })
    return data.status === 'ok'
  } catch {
    return false
  }
}
