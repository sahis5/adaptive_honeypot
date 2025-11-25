const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  send: (channel, data) => {
    // whitelist channels
    const valid = ['toMain']
    if (valid.includes(channel)) ipcRenderer.send(channel, data)
  },
  receive: (channel, func) => {
    const valid = ['fromMain']
    if (valid.includes(channel)) ipcRenderer.on(channel, (event, ...args) => func(...args))
  }
})
