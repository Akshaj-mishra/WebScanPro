import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Globe, ShieldCheck, Zap, ArrowRight, Sparkles, Lock } from 'lucide-react';
import LoadingSpinner from '../components/LoadingSpinner';

const HomePage: React.FC = () => {
  const [url, setUrl] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    if (!url.trim()) {
      setError('Please enter a URL to scan.');
      setLoading(false);
      return;
    }

    // Add URL validation
    try {
      new URL(url);
    } catch {
      setError('Please enter a valid URL (include http:// or https://)');
      setLoading(false);
      return;
    }

    try {
      const response = await fetch('http://localhost:8000/result', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      navigate('/results', { state: { scanResult: data, scannedUrl: url } });
    } catch (err) {
      console.error('Failed to fetch scan results:', err);
      setError('Failed to fetch scan results. Please check the URL and try again. Ensure the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const handleExampleClick = (exampleUrl: string) => {
    setUrl(exampleUrl);
  };

  return (
    <>
      <div className="relative min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 overflow-hidden">
        {/* Animated Background Elements */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob animation-delay-2000"></div>
          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-80 h-80 bg-pink-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob animation-delay-4000"></div>
        </div>

        {/* Grid Pattern Overlay */}
        <div className="absolute inset-0 opacity-50" style={{backgroundImage: `url('data:image/svg+xml,%3Csvg width="60" height="60" xmlns="http://www.w3.org/2000/svg"%3E%3Cdefs%3E%3Cpattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse"%3E%3Cpath d="M 60 0 L 0 0 0 60" fill="none" stroke="rgba(255,255,255,0.03)" stroke-width="1"/%3E%3C/pattern%3E%3C/defs%3E%3Crect width="100%25" height="100%25" fill="url(%23grid)"/%3E%3C/svg%3E')`}}></div>

        <div className="relative min-h-screen flex items-center justify-center p-4">
          <div className="max-w-5xl w-full">
            {/* Hero Section */}
            <div className="text-center mb-12 animate-fade-in-up">
              <div className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-sm rounded-full px-4 py-2 mb-6 border border-white/20">
                <Sparkles className="text-yellow-400" size={18} />
                <span className="text-white/90 text-sm font-medium">AI-Powered Security Scanner</span>
              </div>
              <h1 className="text-6xl md:text-7xl font-bold text-white mb-6 tracking-tight">
                Secure Your
                <span className="bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent"> Digital Presence</span>
              </h1>
              <p className="text-xl text-gray-300 max-w-2xl mx-auto">
                Advanced vulnerability detection and security analysis powered by artificial intelligence. 
                Get instant insights and actionable recommendations.
              </p>
            </div>

            {/* Main Card */}
            <div className="bg-white/10 backdrop-blur-xl rounded-2xl shadow-2xl border border-white/20 p-8 md:p-10 mb-12 animate-fade-in-up animation-delay-200">
              <form onSubmit={handleScan} className="space-y-6">
                <div className="relative">
                  <div className="relative group">
                    <input
                      type="text"
                      className="w-full p-5 pl-14 pr-32 bg-white/90 border-2 border-white/20 rounded-xl focus:ring-4 focus:ring-blue-500/50 focus:border-transparent outline-none transition-all duration-300 text-lg text-gray-900 placeholder-gray-400"
                      placeholder="Enter website URL (e.g., https://example.com)"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      required
                    />
                    <Globe className="absolute left-5 top-1/2 -translate-y-1/2 text-gray-400 group-focus-within:text-blue-500 transition-colors duration-300" size={22} />
                    
                    <button
                      type="submit"
                      className="absolute right-2 top-1/2 -translate-y-1/2 px-6 py-2.5 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-lg hover:from-blue-700 hover:to-purple-700 focus:outline-none focus:ring-4 focus:ring-blue-500/50 flex items-center gap-2 transition-all duration-300 transform hover:scale-105 shadow-lg disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
                      disabled={loading}
                    >
                      {loading ? (
                        <LoadingSpinner />
                      ) : (
                        <>
                          <Search size={18} />
                          <span>Scan Now</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {error && (
                  <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4 animate-shake">
                    <p className="text-red-400 text-sm font-medium text-center">{error}</p>
                  </div>
                )}

                {/* Example URLs */}
                <div className="flex flex-wrap justify-center gap-3 pt-2">
                  <span className="text-gray-400 text-sm">Try examples:</span>
                  {['http://localhost/DVWA/'].map((example) => (
                    <button
                      key={example}
                      type="button"
                      onClick={() => handleExampleClick(example)}
                      className="text-xs px-3 py-1.5 bg-white/10 hover:bg-white/20 rounded-full text-gray-300 hover:text-white transition-all duration-300 border border-white/10"
                    >
                      {example}
                    </button>
                  ))}
                </div>
              </form>
            </div>

            {/* Features Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-fade-in-up animation-delay-400">
              <div className="group bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/10 hover:border-blue-500/50 hover:bg-white/10 transition-all duration-300 transform hover:-translate-y-1">
                <div className="bg-gradient-to-br from-blue-500 to-blue-600 w-14 h-14 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300">
                  <ShieldCheck className="text-white" size={28} />
                </div>
                <h3 className="text-xl font-bold text-white mb-2">Comprehensive Security Scan</h3>
                <p className="text-gray-400 leading-relaxed">
                  Detect OWASP Top 10 vulnerabilities, misconfigurations, and security headers issues with detailed analysis.
                </p>
                <div className="mt-4 flex items-center text-blue-400 text-sm font-medium opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                  Learn more <ArrowRight size={14} className="ml-1" />
                </div>
              </div>

              <div className="group bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/10 hover:border-purple-500/50 hover:bg-white/10 transition-all duration-300 transform hover:-translate-y-1">
                <div className="bg-gradient-to-br from-purple-500 to-purple-600 w-14 h-14 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300">
                  <Zap className="text-white" size={28} />
                </div>
                <h3 className="text-xl font-bold text-white mb-2">AI-Powered Analysis</h3>
                <p className="text-gray-400 leading-relaxed">
                  Get intelligent vulnerability summaries, risk assessments, and actionable remediation steps powered by advanced AI.
                </p>
                <div className="mt-4 flex items-center text-purple-400 text-sm font-medium opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                  Learn more <ArrowRight size={14} className="ml-1" />
                </div>
              </div>

              <div className="group bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/10 hover:border-pink-500/50 hover:bg-white/10 transition-all duration-300 transform hover:-translate-y-1">
                <div className="bg-gradient-to-br from-pink-500 to-pink-600 w-14 h-14 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300">
                  <Lock className="text-white" size={28} />
                </div>
                <h3 className="text-xl font-bold text-white mb-2">Instant Reports & Export</h3>
                <p className="text-gray-400 leading-relaxed">
                  Generate detailed PDF reports, get real-time insights, and track your security posture over time.
                </p>
                <div className="mt-4 flex items-center text-pink-400 text-sm font-medium opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                  Learn more <ArrowRight size={14} className="ml-1" />
                </div>
              </div>
            </div>

            {/* Stats Section */}
            <div className="mt-12 grid grid-cols-3 gap-4 text-center animate-fade-in-up animation-delay-600">
              <div className="bg-white/5 backdrop-blur-sm rounded-lg p-4 border border-white/10">
                <div className="text-2xl font-bold text-white">5 major</div>
                <div className="text-xs text-gray-400 mt-1">Security Checks</div>
              </div>
              <div className="bg-white/5 backdrop-blur-sm rounded-lg p-4 border border-white/10">
                <div className="text-2xl font-bold text-white">Real-time</div>
                <div className="text-xs text-gray-400 mt-1">Analysis</div>
              </div>
              <div className="bg-white/5 backdrop-blur-sm rounded-lg p-4 border border-white/10">
                <div className="text-2xl font-bold text-white">PDF</div>
                <div className="text-xs text-gray-400 mt-1">Export Support</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes blob {
          0%, 100% { transform: translate(0px, 0px) scale(1); }
          33% { transform: translate(30px, -50px) scale(1.1); }
          66% { transform: translate(-20px, 20px) scale(0.9); }
        }
        
        @keyframes fade-in-up {
          from {
            opacity: 0;
            transform: translateY(30px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          25% { transform: translateX(-5px); }
          75% { transform: translateX(5px); }
        }
        
        .animate-blob {
          animation: blob 7s infinite;
        }
        
        .animate-fade-in-up {
          animation: fade-in-up 0.6s ease-out forwards;
        }
        
        .animate-shake {
          animation: shake 0.3s ease-in-out;
        }
        
        .animation-delay-200 {
          animation-delay: 0.2s;
          opacity: 0;
          animation-fill-mode: forwards;
        }
        
        .animation-delay-400 {
          animation-delay: 0.4s;
          opacity: 0;
          animation-fill-mode: forwards;
        }
        
        .animation-delay-600 {
          animation-delay: 0.6s;
          opacity: 0;
          animation-fill-mode: forwards;
        }
      `}</style>
    </>
  );
};

export default HomePage;