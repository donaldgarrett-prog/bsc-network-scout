import { app, BrowserWindow } from 'electron';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
var require = createRequire(import.meta.url);
var __dirname = path.dirname(fileURLToPath(import.meta.url));
process.env.APP_ROOT = path.join(__dirname, '..');
export var VITE_DEV_SERVER_URL = process.env['VITE_DEV_SERVER_URL'];
export var MAIN_DIST = path.join(process.env.APP_ROOT, 'dist-electron');
export var RENDERER_DIST = path.join(process.env.APP_ROOT, 'dist');
process.env.VITE_PUBLIC = VITE_DEV_SERVER_URL
    ? path.join(process.env.APP_ROOT, 'public')
    : RENDERER_DIST;
var win;
function createWindow() {
    win = new BrowserWindow({
        width: 1280,
        height: 820,
        minWidth: 1024,
        minHeight: 700,
        title: 'BSC Network Scout',
        backgroundColor: '#12142a',
        webPreferences: {
            preload: path.join(__dirname, 'preload.mjs'),
            nodeIntegration: false,
            contextIsolation: true,
        },
    });
    win.setMenuBarVisibility(false);
    if (VITE_DEV_SERVER_URL) {
        win.loadURL(VITE_DEV_SERVER_URL);
    }
    else {
        win.loadFile(path.join(RENDERER_DIST, 'index.html'));
    }
}
app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') {
        app.quit();
        win = null;
    }
});
app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});
app.whenReady().then(createWindow);
