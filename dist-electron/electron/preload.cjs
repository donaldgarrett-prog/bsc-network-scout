const { ipcRenderer, contextBridge } = require('electron');
console.log('BSC PRELOAD RUNNING');
contextBridge.exposeInMainWorld('bscScout', {
    startScan: (subnet) => ipcRenderer.invoke('bsc:start-scan', subnet),
    detectSubnet: () => ipcRenderer.invoke('bsc:detect-subnet'),
    generatePdf: (data) => ipcRenderer.invoke('bsc:generate-pdf', data),
    onScanProgress: (callback) => {
        ipcRenderer.on('bsc:scan-progress', (_event, data) => callback(data));
    },
    removeScanProgress: () => {
        ipcRenderer.removeAllListeners('bsc:scan-progress');
    }
});
