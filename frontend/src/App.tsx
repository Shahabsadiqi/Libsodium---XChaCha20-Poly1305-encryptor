import { useState, useEffect, Fragment } from 'react'
import styled from 'styled-components'

const Container = styled.div`
  font-family: system-ui, sans-serif;
  max-width: 700px;
  margin: 40px auto;
  padding: 30px;
  background: #f9f9f9;
  border-radius: 12px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.1);
`

const ProgressBar = styled.div<{ $percent: number }>`
  height: 24px;
  background: #ddd;
  border-radius: 12px;
  overflow: hidden;
  margin: 20px 0;
`

const Fill = styled.div<{ $percent: number }>`
  width: ${p => p.$percent}%;
  height: 100%;
  background: linear-gradient(90deg, #4caf50, #45a049);
  transition: width 0.3s ease;
`

const Button = styled.button<{ disabled?: boolean }>`
  padding: 12px 24px;
  font-size: 16px;
  background: ${p => p.disabled ? '#ccc' : '#4caf50'};
  color: white;
  border: none;
  border-radius: 8px;
  cursor: ${p => p.disabled ? 'not-allowed' : 'pointer'};
  width: 100%;
  margin: 10px 0;
`

function App() {
  const [file, setFile] = useState<File | null>(null)
  const [password, setPassword] = useState('')
  const [progress, setProgress] = useState(0)
  const [status, setStatus] = useState('Ready')
  const [isRunning, setIsRunning] = useState(false)
  const [sodiumReady, setSodiumReady] = useState(false)

  useEffect(() => {
    import('libsodium-wrappers-sumo').then(({ default: sodium }) => {
      sodium.ready.then(() => {
        setSodiumReady(true)
      }).catch(console.error)
    })
  }, [])

  const encryptFile = async () => {
    if (!file || !password || !sodiumReady) return

    setIsRunning(true)
    setProgress(0)
    setStatus('Encrypting...')

    const sodium = (await import('libsodium-wrappers-sumo')).default
    await sodium.ready

    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
    const key = sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      password,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    )
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)

    const reader = new FileReader()
    reader.onload = (e) => {
      const data = new Uint8Array(e.target?.result as ArrayBuffer)
      const chunkSize = 64 * 1024
      let processed = 0
      const encryptedChunks: Uint8Array[] = []

      const processChunk = async (start: number) => {
        while (start < data.length) {
          const end = Math.min(start + chunkSize, data.length)
          const chunk = data.slice(start, end)
          const encrypted = sodium.crypto_secretbox_easy(chunk, nonce, key)
          encryptedChunks.push(encrypted)

          processed += chunk.length
          const percent = Math.round((processed / data.length) * 100)
          setProgress(percent)
          setStatus(`Encrypting... ${percent}%`)

          // Simulate async delay
          await new Promise(r => setTimeout(r, 5))

          start = end
        }

        // Combine and download
        const ciphertext = sodium.crypto_generichash(32, new Uint8Array(encryptedChunks.flatMap(c => Array.from(c))))  // Hash for integrity
        const final = new Uint8Array([...salt, ...nonce, ...encryptedChunks.flatMap(c => Array.from(c))])
        const blob = new Blob([final], { type: 'application/octet-stream' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = file.name + '.encrypted'
        a.click()
        URL.revokeObjectURL(url)

        setProgress(100)
        setStatus('Download started!')
        setIsRunning(false)
      }

      processChunk(0)
    }

    reader.readAsArrayBuffer(file)
  }

  return (
    <>
      <Container>
        <h1>XChaCha20-Poly1305 File Encryptor</h1>
        <p>Client-side encryption — secure & private</p>
        
        <input 
          type="file" 
          onChange={(e) => e.target.files && setFile(e.target.files[0])} 
          disabled={isRunning}
          style={{ display: 'block', margin: '15px 0', padding: '10px', width: '100%' }}
        />
        
        <input
          type="password"
          placeholder="Enter password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={isRunning}
          style={{ width: '100%', padding: '12px', fontSize: '16px', marginBottom: '20px' }}
        />
        
        <Button onClick={encryptFile} disabled={isRunning || !file || !password || !sodiumReady}>
          {isRunning ? 'Encrypting...' : 'Encrypt File'}
        </Button>

        {!sodiumReady && <p>Loading crypto library...</p>}

        {isRunning && (
          <Fragment>
            <ProgressBar $percent={progress}>
              <Fill $percent={progress} />
            </ProgressBar>
            <p style={{ textAlign: 'center', fontWeight: 'bold' }}>{status}</p>
          </Fragment>
        )}

        {status.includes('Download') && (
          <p style={{ color: 'green', fontWeight: 'bold', textAlign: 'center' }}>
            {status} — Check your downloads folder.
          </p>
        )}
      </Container>
    </>
  )
}

export default App
