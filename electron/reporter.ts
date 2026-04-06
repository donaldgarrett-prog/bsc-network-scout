import { ipcMain, dialog, app } from 'electron'
import path from 'node:path'
import fs from 'node:fs'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const PDFDocument = require('pdfkit')

const NAVY = '#1a1d35'
const GOLD = '#c9a84c'
const RED = '#e74c3c'
const AMBER = '#f39c12'
const GREEN = '#2ecc71'
const WHITE = '#ffffff'
const GRAY = '#8892b0'

function riskColor(risk: string): string {
  return risk === 'high' ? RED : risk === 'medium' ? AMBER : GREEN
}

export function registerReportHandlers() {
  ipcMain.handle('bsc:generate-pdf', async (_event, { hosts, subnet }) => {
    try {
      // Show save dialog
      const { filePath, canceled } = await dialog.showSaveDialog({
        title: 'Save BSC Network Scout Report',
        defaultPath: path.join(app.getPath('desktop'), `BSC_Network_Scan_${new Date().toISOString().split('T')[0]}.pdf`),
        filters: [{ name: 'PDF Files', extensions: ['pdf'] }]
      })

      if (canceled || !filePath) return { success: false, reason: 'canceled' }

      const doc = new PDFDocument({ margin: 50, size: 'LETTER' })
      const stream = fs.createWriteStream(filePath)
      doc.pipe(stream)

      // ── HEADER ──
      doc.rect(0, 0, 612, 80).fill(NAVY)
      doc.fontSize(22).fillColor(GOLD).font('Helvetica-Bold')
        .text('BRAVO SIX CYBER LLC', 50, 20)
      doc.fontSize(10).fillColor(WHITE).font('Helvetica')
        .text('Service-Disabled Veteran-Owned Small Business  ·  CISSP  ·  CICP', 50, 48)
      doc.fontSize(10).fillColor(GOLD)
        .text('NETWORK SECURITY ASSESSMENT REPORT', 50, 62)

      // ── SCAN SUMMARY ──
      const high   = hosts.filter((h: any) => h.risk === 'high').length
      const medium = hosts.filter((h: any) => h.risk === 'medium').length
      const low    = hosts.filter((h: any) => h.risk === 'low').length
      const score  = Math.max(10, Math.round(100 - high * 18 - medium * 7 - low * 1))
      const grade  = score >= 80 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F'

      doc.moveDown(3)
      doc.fontSize(12).fillColor(NAVY).font('Helvetica-Bold').text('SCAN SUMMARY', 50)
      doc.moveTo(50, doc.y + 4).lineTo(562, doc.y + 4).stroke(NAVY)
      doc.moveDown(0.5)

      const summaryY = doc.y
      // Score box
      doc.rect(50, summaryY, 120, 70).fill('#f0f2ff')
      doc.fontSize(28).fillColor(riskColor(high > 0 ? 'high' : medium > 0 ? 'medium' : 'low'))
        .font('Helvetica-Bold').text(`${score}/100`, 50, summaryY + 8, { width: 120, align: 'center' })
      doc.fontSize(10).fillColor(NAVY).font('Helvetica')
        .text(`Security Score  ·  Grade: ${grade}`, 50, summaryY + 46, { width: 120, align: 'center' })

      // Stats
      doc.fontSize(11).fillColor(NAVY).font('Helvetica-Bold')
      doc.text(`Network:  ${subnet}`, 190, summaryY + 8)
      doc.text(`Scan Date:  ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`, 190, summaryY + 26)
      doc.text(`Total Hosts:  ${hosts.length}`, 190, summaryY + 44)
      doc.fillColor(RED).text(`High Risk:  ${high}`, 380, summaryY + 8)
      doc.fillColor(AMBER).text(`Medium Risk:  ${medium}`, 380, summaryY + 26)
      doc.fillColor(GREEN).text(`Low Risk:  ${low}`, 380, summaryY + 44)

      // ── HOST TABLE ──
      doc.moveDown(4)
      doc.fontSize(12).fillColor(NAVY).font('Helvetica-Bold').text('DISCOVERED HOSTS', 50)
      doc.moveTo(50, doc.y + 4).lineTo(562, doc.y + 4).stroke(NAVY)
      doc.moveDown(0.5)

      // Table header
      let y = doc.y
      doc.rect(50, y, 512, 22).fill(NAVY)
      doc.fontSize(9).fillColor(WHITE).font('Helvetica-Bold')
      doc.text('IP ADDRESS', 58, y + 7)
      doc.text('DEVICE NAME', 148, y + 7)
      doc.text('OPEN PORTS', 318, y + 7)
      doc.text('RISK', 468, y + 7)
      y += 22

      // Table rows
      for (const host of hosts) {
        if (y > 700) {
          doc.addPage()
          y = 50
        }

        const rowColor = hosts.indexOf(host) % 2 === 0 ? '#f8f9fc' : WHITE
        doc.rect(50, y, 512, 22).fill(rowColor)

        doc.fontSize(8).fillColor('#333333').font('Helvetica')
        doc.text(host.ip, 58, y + 7, { width: 85 })
        doc.text(host.name || 'Unknown', 148, y + 7, { width: 165 })
        doc.text(host.ports.length ? host.ports.slice(0, 6).join(', ') : 'None', 318, y + 7, { width: 145 })

        const rc = riskColor(host.risk)
        doc.rect(468, y + 4, 42, 14).fill(rc)
        doc.fontSize(7).fillColor(WHITE).font('Helvetica-Bold')
          .text(host.risk.toUpperCase(), 468, y + 7, { width: 42, align: 'center' })

        y += 22
      }

      // ── FINDINGS ──
      doc.addPage()
      doc.fontSize(12).fillColor(NAVY).font('Helvetica-Bold').text('DETAILED FINDINGS', 50, 50)
      doc.moveTo(50, doc.y + 4).lineTo(562, doc.y + 4).stroke(NAVY)
      doc.moveDown(0.5)

      for (const host of hosts.filter((h: any) => h.risk !== 'low')) {
        if (doc.y > 680) doc.addPage()

        const rc = riskColor(host.risk)
        doc.rect(50, doc.y, 512, 24).fill(rc)
        doc.fontSize(10).fillColor(WHITE).font('Helvetica-Bold')
          .text(`${host.ip}  —  ${host.name}  —  ${host.risk.toUpperCase()} RISK`, 58, doc.y + 7)
        doc.moveDown(0.3)

        for (const issue of host.issues) {
          doc.fontSize(9).fillColor('#333333').font('Helvetica')
            .text(`-  ${issue}`, 65, doc.y, { width: 490 })
          doc.moveDown(0.2)
        }
        doc.moveDown(0.5)
      }

      // ── BSC CTA ──
      if (doc.y > 600) doc.addPage()
      doc.moveDown(1)

      const ctaY = doc.y
      doc.rect(50, ctaY, 512, 110).fill(NAVY)
      doc.fontSize(13).fillColor(GOLD).font('Helvetica-Bold')
        .text('BRAVO SIX CYBER LLC — PROFESSIONAL ASSESSMENT', 65, ctaY + 12)
      doc.fontSize(9).fillColor(WHITE).font('Helvetica')
        .text(
          `This automated scan identified ${high} high-risk and ${medium} medium-risk findings on your network. ` +
          'A Bravo Six certified assessment goes deeper — credentialed internal scanning, configuration review, ' +
          'policy analysis, and a written remediation roadmap delivered by a CISSP-certified SDVOSB consultant.',
          65, ctaY + 32, { width: 480 }
        )
      doc.fontSize(9).fillColor(GOLD).font('Helvetica-Bold')
        .text('info@bravosixcyber.com  ·  656.245.8307  ·  bravosixcyber.com  ·  SDVOSB  ·  CISSP  ·  CICP',
          65, ctaY + 85, { width: 480 })

      // ── FOOTER ──
      const pageRange = doc.bufferedPageRange()
      const pageCount = pageRange.count
      for (let i = 0; i < pageCount; i++) {
        doc.switchToPage(pageRange.start + i)
        doc.rect(0, 762, 612, 30).fill(NAVY)
        doc.fontSize(7).fillColor(GRAY).font('Helvetica')
          .text(
            `BSC Network Scout  ·  Bravo Six Cyber LLC  ·  CONFIDENTIAL  ·  Page ${i + 1} of ${pageCount}`,
            50, 771, { width: 512, align: 'center' }
          )
      }

      doc.end()

      await new Promise<void>((resolve, reject) => {
        stream.on('finish', resolve)
        stream.on('error', reject)
      })

      return { success: true, filePath }

    } catch (err: any) {
      console.error('PDF error:', err)
      return { success: false, reason: err.message }
    }
  })
}
