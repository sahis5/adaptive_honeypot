const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const fs = require('fs')

// --- SAFETY: set custom user data path so Chromium cache is writable
// Creates a folder inside the user's appData for this app.
const safeUserData = path.join(app.getPath('appData'), 'AdaptiveHoneypot', 'UserData')
try {
  fs.mkdirSync(safeUserData, { recursive: true })
  app.setPath('userData', safeUserData)
} catch (e) {
  // ignore if cannot create, fallback to default
  console.error('Could not set custom userData path:', e)
}

// Optionally disable GPU cache / GPU (useful on some Windows installs)
app.commandLine.appendSwitch('disable-gpu')
app.commandLine.appendSwitch('disable-gpu-compositing')
app.commandLine.appendSwitch('disable-software-rasterizer')

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  })

  // Open devtools in development unconditionally (helpful for debugging)
  mainWindow.webContents.openDevTools({ mode: 'detach' })

  if (process.env.NODE_ENV === 'development') {
    mainWindow.loadURL('http://localhost:3000')
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'))
  }
}

app.whenReady().then(() => {
  createWindow()

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit()
})
