const { ipcRenderer, contextBridge } = require('electron')

console.log('BSC PRELOAD RUNNING')

contextBridge.exposeInMainWorld('bscScout', {
  startScan: (subnet: string) => ipcRenderer.invoke('bsc:start-scan', subnet),
  onScanProgress: (callback: (data: any) => void) => {
    ipcRenderer.on('bsc:scan-progress', (_event: any, data: any) => callback(data))
  },
  removeScanProgress: () => {
    ipcRenderer.removeAllListeners('bsc:scan-progress')
  },
  test: () => 'BSC preload connected'
})
