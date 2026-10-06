package com.shadownetguardian.report;

import com.lowagie.text.Document;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ScanResult;
import java.io.FileOutputStream;
import java.time.format.DateTimeFormatter;

public class PdfReportGenerator {
    
    public static void generateReport(ScanResult result, String filePath) {
        if (result == null) {
            System.out.println("No scan result available to generate a report.");
            return;
        }

        Document document = new Document();
        try {
            PdfWriter.getInstance(document, new FileOutputStream(filePath));
            document.open();

            Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18);
            Paragraph title = new Paragraph("ShadowNet Guardian - Scan Report", titleFont);
            title.setAlignment(Paragraph.ALIGN_CENTER);
            document.add(title);
            
            document.add(new Paragraph(" ")); // Empty line

            document.add(new Paragraph("Target URL: " + result.targetUrl()));
            document.add(new Paragraph("Scan Time: " + result.timestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
            document.add(new Paragraph("Total Risk Score: " + result.totalScore() + "/100"));
            document.add(new Paragraph("Classification: " + result.classification()));
            
            document.add(new Paragraph(" "));
            
            PdfPTable table = new PdfPTable(4);
            table.setWidthPercentage(100);
            table.setWidths(new float[]{2f, 1f, 1f, 3f});
            
            // Header
            PdfPCell cell = new PdfPCell(new Phrase("Detector"));
            table.addCell(cell);
            table.addCell("Triggered");
            table.addCell("Score");
            table.addCell("Reason");
            
            // Data
            for (DetectionResult dr : result.detectionResults()) {
                table.addCell(dr.detectorName());
                table.addCell(dr.triggered() ? "YES" : "NO");
                table.addCell(String.valueOf(dr.scoreContribution()));
                table.addCell(dr.reason());
            }
            
            document.add(table);
            
            System.out.println("PDF report generated successfully at: " + filePath);
        } catch (Exception e) {
            System.err.println("Error generating PDF report: " + e.getMessage());
        } finally {
            if (document.isOpen()) {
                document.close();
            }
        }
    }
}
