import React, { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';
import { Download, ChevronLeft, ShieldAlert } from 'lucide-react';

interface ScanResult {
  summary: string;
  risk_score: number;
  vulnerabilities: string;
}

const ResultPage: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scannedUrl, setScannedUrl] = useState<string | null>(null);
  const reportRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (location.state?.scanResult && location.state?.scannedUrl) {
      setScanResult(location.state.scanResult);
      setScannedUrl(location.state.scannedUrl);
    } else {
      // If direct access or refresh, try to get from localStorage or redirect
      const storedResult = localStorage.getItem('lastScanResult');
      const storedUrl = localStorage.getItem('lastScannedUrl');
      if (storedResult && storedUrl) {
        setScanResult(JSON.parse(storedResult));
        setScannedUrl(storedUrl);
      } else {
        navigate('/'); // Redirect to home if no data
      }
    }
  }, [location.state, navigate]);

  useEffect(() => {
    // Store result in localStorage for persistence across refreshes
    if (scanResult && scannedUrl) {
      localStorage.setItem('lastScanResult', JSON.stringify(scanResult));
      localStorage.setItem('lastScannedUrl', scannedUrl);
    }
  }, [scanResult, scannedUrl]);

  const handleDownloadPdf = async () => {
    if (reportRef.current) {
      const input = reportRef.current;
      const canvas = await html2canvas(input, { scale: 2, useCORS: true }); // Scale up for better quality
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const imgWidth = 210; // A4 width in mm
      const pageHeight = 297; // A4 height in mm
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      let heightLeft = imgHeight;
      let position = 0;

      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;

      while (heightLeft >= 0) {
        position = heightLeft - imgHeight;
        pdf.addPage();
        pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
        heightLeft -= pageHeight;
      }
      pdf.save(`WebScanPro_Report_${new Date().toISOString().split('T')[0]}.pdf`);
    }
  };

  if (!scanResult) {
    return (
      <div className="flex justify-center items-center min-h-[calc(100vh-64px)] text-xl text-gray-600">
        Loading report or no scan result found.
      </div>
    );
  };

  const getRiskColor = (score: number) => {
    if (score >= 8) return 'text-red-600';
    if (score >= 5) return 'text-orange-500';
    return 'text-green-600';
  };

  const getRiskLabel = (score: number) => {
    if (score >= 8) return 'High Risk';
    if (score >= 5) return 'Medium Risk';
    return 'Low Risk';
  };

  return (
    <div className="min-h-[calc(100vh-64px)] bg-gradient-to-br from-gray-50 to-blue-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="container mx-auto max-w-4xl bg-white rounded-xl shadow-2xl overflow-hidden animate-fade-in">
        <div className="bg-gradient-to-r from-dark to-primary text-white p-6 sm:p-8 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <ShieldAlert className="w-10 h-10 text-secondary" />
            <div>
              <h1 className="text-3xl font-bold tracking-tight">WebScanPro Security Report</h1>
              {scannedUrl && <p className="text-sm opacity-90">Scanned URL: <span className="font-medium break-all">{scannedUrl}</span></p>}
            </div>
          </div>
          <div className="text-right">
            <p className="text-lg">Risk Score:</p>
            <p className={`text-4xl font-extrabold ${getRiskColor(scanResult.risk_score)}`}>{scanResult.risk_score}/100</p>
            <span className={`text-sm font-semibold px-2 py-1 rounded-full ${scanResult.risk_score >= 8 ? 'bg-red-700' : scanResult.risk_score >= 5 ? 'bg-orange-600' : 'bg-green-700'} text-white`}>
              {getRiskLabel(scanResult.risk_score)}
            </span>
          </div>
        </div>

        <div className="p-6 sm:p-8" ref={reportRef}> {/* PDF content wrapper */}
          <div className="mb-10">
            <h2 className="text-3xl font-bold text-dark mb-4 border-b-2 border-primary pb-2 flex items-center gap-2">
              <span className="text-primary">AI-Powered Summary</span>
            </h2>
            <div className="prose max-w-none text-gray-800 leading-relaxed">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{scanResult.summary}</ReactMarkdown>
            </div>
          </div>

          <div className="mb-10">
            <h2 className="text-3xl font-bold text-dark mb-4 border-b-2 border-secondary pb-2 flex items-center gap-2">
              <span className="text-secondary">Vulnerability Details</span>
            </h2>
            <div className="prose max-w-none text-gray-800 leading-relaxed">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{scanResult.vulnerabilities}</ReactMarkdown>
            </div>
          </div>

          <div className="flex justify-between items-center mt-10 pt-6 border-t border-gray-200">
            <button
              onClick={() => navigate('/')}
              className="px-6 py-3 bg-gray-200 text-dark font-semibold rounded-lg hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-400 flex items-center gap-2 transition-all duration-300"
            >
              <ChevronLeft size={20} /> Back to Scan
            </button>
            <button
              onClick={handleDownloadPdf}
              className="px-6 py-3 bg-primary text-white font-semibold rounded-lg shadow-md hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-blue-400 flex items-center gap-2 transition-all duration-300 transform hover:-translate-y-1"
            >
              <Download size={20} /> Download PDF
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResultPage;