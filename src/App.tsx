import React, { useState } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  Bars3Icon,
  XMarkIcon,
  PhotoIcon,
  DocumentIcon,
  CodeBracketIcon,
  CircleStackIcon,
  ArrowDownTrayIcon,
  ArrowRightIcon,
  ArrowLeftIcon,
  ChartBarIcon,
  EyeIcon,
  TableCellsIcon,
  FolderIcon,
  BookOpenIcon,
  Squares2X2Icon
} from '@heroicons/react/24/outline';

import { analyzerManager } from './engine';
import { AnalysisResult } from './engine/types';
import { downloadExtractedFile, downloadFilesAsZip } from './utils/download';
import { FindingsCorrelator, ComprehensiveReport } from './engine/correlator';
import { DocumentationView } from './components/DocumentationView';

interface ToolCardConfig {
  id: string;
  name: string;
  category: string;
  description: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  iconBg: string;
  iconColor: string;
}

const TOOL_CARDS: ToolCardConfig[] = [
  {
    id: 'steghide',
    name: 'Steghide',
    category: 'JPEG, BMP, WAV',
    description: 'Extract hidden data from images (JPEG, BMP, WAV).',
    icon: PhotoIcon,
    iconBg: 'bg-pink-500/10 border-pink-500/20',
    iconColor: 'text-neonPink'
  },
  {
    id: 'binwalk',
    name: 'Binwalk',
    category: 'Firmware & Containers',
    description: 'Firmware analysis and embedded file extraction.',
    icon: DocumentIcon,
    iconBg: 'bg-blue-500/10 border-blue-500/20',
    iconColor: 'text-blue-400'
  },
  {
    id: 'strings',
    name: 'Strings',
    category: 'Binaries & Streams',
    description: 'Extract printable characters from binary files.',
    icon: CodeBracketIcon,
    iconBg: 'bg-emerald-500/10 border-emerald-500/20',
    iconColor: 'text-emerald-400'
  },
  {
    id: 'zsteg',
    name: 'Zsteg',
    category: 'PNG & BMP Stego',
    description: 'Advanced PNG & BMP steganography analysis.',
    icon: Squares2X2Icon,
    iconBg: 'bg-purple-500/10 border-purple-500/20',
    iconColor: 'text-purple-400'
  },
  {
    id: 'metadata',
    name: 'Metadata Explorer',
    category: 'EXIF, GPS, XMP, IPTC',
    description: 'Inspect EXIF, GPS, XMP, IPTC and container metadata.',
    icon: CircleStackIcon,
    iconBg: 'bg-amber-500/10 border-amber-500/20',
    iconColor: 'text-amber-400'
  },
  {
    id: 'rgb',
    name: 'RGB Viewer',
    category: 'Bit Planes & Channels',
    description: 'Analyze color channels and bit-plane data.',
    icon: EyeIcon,
    iconBg: 'bg-cyan-500/10 border-cyan-500/20',
    iconColor: 'text-neonBlue'
  },
  {
    id: 'entropy',
    name: 'Entropy',
    category: 'Shannon Randomness',
    description: 'Analyze block entropy to detect encrypted and compressed payloads.',
    icon: ChartBarIcon,
    iconBg: 'bg-yellow-500/10 border-yellow-500/20',
    iconColor: 'text-yellow-400'
  }
];

export default function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [activeToolId, setActiveToolId] = useState<string | null>(null); // null = Home overview, 'docs' = Documentation page
  const [drawerOpen, setDrawerOpen] = useState<boolean>(false);
  const [analysisResults, setAnalysisResults] = useState<Record<string, AnalysisResult>>({});
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [progressStatus, setProgressStatus] = useState<string>('');
  const [progressPercent, setProgressPercent] = useState<number>(0);
  const [steghidePassword, setSteghidePassword] = useState<string>('');
  const [comprehensiveReport, setComprehensiveReport] = useState<ComprehensiveReport | null>(null);

  // Dropzone handling
  const { getRootProps, getInputProps, isDragActive, open: openFilePicker } = useDropzone({
    noClick: false,
    noKeyboard: false,
    accept: {
      'image/*': ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg', '.tiff', '.ico'],
      'video/*': ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv', '.m4v'],
      'audio/*': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a'],
      'application/pdf': ['.pdf'],
      'application/zip': ['.zip', '.rar', '.7z'],
      'application/x-executable': ['.exe'],
      'text/*': ['.txt', '.log', '.csv', '.json', '.xml', '.html', '.css', '.js'],
      'application/octet-stream': []
    },
    maxSize: 100 * 1024 * 1024,
    onDrop: (acceptedFiles: File[]) => {
      const file = acceptedFiles[0];
      if (file) {
        handleFileSelect(file);
      }
    }
  });

  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
    setAnalysisResults({});
    setComprehensiveReport(null);
    setImagePreview(null);

    if (file.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (typeof e.target?.result === 'string') {
          setImagePreview(e.target.result);
        }
      };
      reader.readAsDataURL(file);
    }
  };

  const removeFile = (e?: React.MouseEvent) => {
    e?.stopPropagation();
    setSelectedFile(null);
    setImagePreview(null);
    setAnalysisResults({});
    setComprehensiveReport(null);
  };

  const runAnalysisForTool = async (toolId: string) => {
    if (!selectedFile) return;

    setIsAnalyzing(true);
    setProgressPercent(20);
    setProgressStatus(`Running ${toolId}...`);

    try {
      const result = await analyzerManager.run(
        toolId,
        selectedFile,
        { password: steghidePassword },
        {
          onProgress: (pct, msg) => {
            setProgressPercent(pct);
            setProgressStatus(msg);
          }
        }
      );

      setAnalysisResults(prev => ({ ...prev, [toolId]: result }));
    } catch (err: any) {
      console.error('Analyzer error:', err);
      alert(`Analysis error: ${err.message || String(err)}`);
    } finally {
      setIsAnalyzing(false);
      setProgressStatus('');
    }
  };

  const runAnalyzeAll = async () => {
    if (!selectedFile) return;

    setIsAnalyzing(true);
    setProgressPercent(0);
    setProgressStatus('Executing all analysis tools...');

    try {
      const allResults = await analyzerManager.runAll(
        selectedFile,
        { password: steghidePassword },
        {
          onProgress: (pct, msg) => {
            setProgressPercent(pct);
            setProgressStatus(msg);
          }
        }
      );

      const resultMap: Record<string, AnalysisResult> = {};
      for (const [id, res] of allResults.entries()) {
        resultMap[id] = res;
      }

      setAnalysisResults(resultMap);
      const report = FindingsCorrelator.correlate(allResults);
      setComprehensiveReport(report);
    } catch (err: any) {
      console.error('Analyze all error:', err);
      alert(`Analyze All error: ${err.message || String(err)}`);
    } finally {
      setIsAnalyzing(false);
      setProgressStatus('');
    }
  };

  const navigateToTool = (toolId: string | null) => {
    setActiveToolId(toolId);
    setDrawerOpen(false);
    if (toolId && toolId !== 'docs' && selectedFile && !analysisResults[toolId]) {
      runAnalysisForTool(toolId);
    }
  };

  return (
    <div className="min-h-screen bg-dark text-gray-200 flex flex-col font-sans selection:bg-neonPink selection:text-white">
      {/* Top Navigation Bar */}
      <header className="bg-surface/90 border-b border-borderDark sticky top-0 z-40">
        <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setDrawerOpen(true)}
              className="p-2 -ml-2 text-gray-400 hover:text-white hover:bg-card rounded-lg transition-colors"
              aria-label="Open Navigation Drawer"
            >
              <Bars3Icon className="h-6 w-6" />
            </button>

            <div
              onClick={() => navigateToTool(null)}
              className="flex items-center space-x-3 cursor-pointer group"
            >
              <img src="/logo.svg" alt="The Hidden Bytes" className="h-7 w-7" />
              <div>
                <h1 className="text-lg font-bold text-white tracking-tight leading-none">
                  the hidden <span className="text-neonPink">bytes</span>
                </h1>
                <p className="text-[10px] font-semibold text-gray-400 tracking-wider uppercase mt-0.5">
                  Digital Forensics Workbench
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <button
              onClick={() => navigateToTool('docs')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors ${
                activeToolId === 'docs'
                  ? 'bg-card text-white border border-borderDark'
                  : 'text-gray-400 hover:text-white hover:bg-card/50'
              }`}
            >
              <BookOpenIcon className="h-4 w-4 text-neonPink" />
              <span className="hidden sm:inline">Documentation</span>
            </button>
            <span className="text-xs font-mono text-gray-400">v 2.0.0</span>
          </div>
        </div>
      </header>

      {/* Navigation Drawer (Sidebar on demand) */}
      {drawerOpen && (
        <div className="fixed inset-0 z-50 flex">
          <div
            className="fixed inset-0 bg-black/60 transition-opacity"
            onClick={() => setDrawerOpen(false)}
          />

          <div className="relative w-80 max-w-full bg-surface border-r border-borderDark flex flex-col z-10 shadow-2xl">
            <div className="p-5 border-b border-borderDark flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <img src="/logo.svg" alt="Logo" className="h-6 w-6" />
                <span className="font-bold text-white text-sm">the hidden <span className="text-neonPink">bytes</span></span>
              </div>
              <button
                onClick={() => setDrawerOpen(false)}
                className="p-1.5 text-gray-400 hover:text-white hover:bg-card rounded-lg"
              >
                <XMarkIcon className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-1">
              <div className="text-[10px] font-bold text-gray-400 uppercase tracking-wider px-3 py-2">
                Forensics Tools
              </div>
              <button
                onClick={() => navigateToTool(null)}
                className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors ${
                  activeToolId === null ? 'bg-card text-white border border-borderDark' : 'text-gray-400 hover:text-white hover:bg-card/50'
                }`}
              >
                <FolderIcon className="h-4 w-4 text-neonPink" />
                <span>Overview & Upload</span>
              </button>

              {TOOL_CARDS.map(tool => (
                <button
                  key={tool.id}
                  onClick={() => navigateToTool(tool.id)}
                  className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors ${
                    activeToolId === tool.id ? 'bg-card text-white border border-borderDark' : 'text-gray-400 hover:text-white hover:bg-card/50'
                  }`}
                >
                  <tool.icon className={`h-4 w-4 ${tool.iconColor}`} />
                  <span>{tool.name}</span>
                </button>
              ))}

              <div className="pt-4 pb-2">
                <div className="border-t border-borderDark" />
              </div>

              <div className="text-[10px] font-bold text-gray-400 uppercase tracking-wider px-3 py-2">
                Manual & Handbook
              </div>

              <button
                onClick={() => navigateToTool('docs')}
                className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors ${
                  activeToolId === 'docs' ? 'bg-card text-white border border-borderDark' : 'text-gray-400 hover:text-white hover:bg-card/50'
                }`}
              >
                <BookOpenIcon className="h-4 w-4 text-neonPink" />
                <span>Documentation & Roadmap</span>
              </button>
            </div>

            <div className="p-4 border-t border-borderDark text-[11px] text-gray-400 flex justify-between items-center">
              <span>The Hidden Bytes</span>
              <span className="font-mono">v 2.0.0</span>
            </div>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
        {/* VIEW: Documentation Book View */}
        {activeToolId === 'docs' ? (
          <DocumentationView onBack={() => setActiveToolId(null)} />
        ) : activeToolId === null ? (
          /* VIEW: Home Overview */
          <div className="space-y-12">
            {/* 2-Column Hero & Dropzone Section */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
              {/* Left Column: Typography & Positioning */}
              <div className="lg:col-span-6 space-y-4">
                <div className="text-xs font-semibold text-gray-400 uppercase tracking-widest font-mono">
                  UNCOVER &bull; ANALYZE &bull; UNDERSTAND
                </div>
                <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black text-white tracking-tight leading-tight">
                  the hidden <span className="text-neonPink">bytes</span>
                </h1>
                <p className="text-sm sm:text-base text-gray-400 max-w-lg leading-relaxed pt-1">
                  A browser-based suite for steganography analysis, firmware carving, and digital forensics.
                </p>
              </div>

              {/* Right Column: Interactive Dropzone Card */}
              <div className="lg:col-span-6">
                {!selectedFile ? (
                  <div
                    {...getRootProps()}
                    className={`border-2 border-dashed rounded-2xl p-8 sm:p-10 text-center cursor-pointer transition-all bg-card/60 ${
                      isDragActive
                        ? 'border-neonBlue bg-card/90 scale-[1.01]'
                        : 'border-borderDark hover:border-gray-500 hover:bg-card'
                    }`}
                  >
                    <input {...getInputProps()} />
                    <div className="flex flex-col items-center justify-center space-y-4">
                      <div className="h-14 w-14 rounded-xl bg-surface border border-borderDark flex items-center justify-center text-gray-400">
                        <DocumentIcon className="h-8 w-8" />
                      </div>
                      <div>
                        <h3 className="text-base font-semibold text-white">Drag and drop a file here</h3>
                        <p className="text-xs text-gray-400 mt-1">or click to browse</p>
                      </div>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          openFilePicker();
                        }}
                        className="px-6 py-2.5 bg-neonPink text-white text-xs font-bold rounded-lg hover:opacity-90 transition-all flex items-center space-x-2 shadow-lg shadow-neonPink/20"
                      >
                        <FolderIcon className="h-4 w-4" />
                        <span>Select File</span>
                      </button>
                      <p className="text-[11px] text-gray-400 pt-1">
                        Supports images, firmware, archives, PDFs, audio, and binaries.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="bg-card border border-borderDark rounded-2xl p-6 sm:p-7 shadow-xl space-y-5">
                    <div className="flex items-center space-x-4">
                      {imagePreview ? (
                        <img src={imagePreview} alt="Preview" className="h-16 w-16 object-cover rounded-xl border border-borderDark" />
                      ) : (
                        <div className="h-16 w-16 rounded-xl bg-surface border border-borderDark flex items-center justify-center text-neonBlue">
                          <DocumentIcon className="h-8 w-8" />
                        </div>
                      )}
                      <div className="flex-1 min-w-0">
                        <h3 className="text-base font-bold text-white truncate">{selectedFile.name}</h3>
                        <p className="text-xs text-gray-400 mt-0.5">
                          {selectedFile.type || 'Binary file'} &bull; {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB
                        </p>
                      </div>
                      <button
                        onClick={removeFile}
                        className="text-xs text-gray-400 hover:text-red-400 p-2 rounded-lg hover:bg-surface transition-colors"
                        title="Remove File"
                      >
                        <XMarkIcon className="h-5 w-5" />
                      </button>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-borderDark">
                      <button
                        onClick={runAnalyzeAll}
                        disabled={isAnalyzing}
                        className="flex-1 px-5 py-2.5 bg-neonPink text-white text-xs font-bold rounded-lg hover:opacity-90 disabled:opacity-50 transition-all shadow-md"
                      >
                        {isAnalyzing ? 'Running Analysis...' : 'Analyze All Tools'}
                      </button>
                      <button
                        onClick={() => openFilePicker()}
                        className="px-4 py-2.5 bg-surface border border-borderDark text-gray-300 text-xs font-medium rounded-lg hover:text-white hover:border-gray-500 transition-colors"
                      >
                        Change File
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Progress Bar (if running) */}
            {isAnalyzing && (
              <div className="bg-card border border-borderDark rounded-xl p-4 shadow-lg">
                <div className="flex justify-between text-xs text-gray-300 mb-1.5 font-mono">
                  <span>{progressStatus || 'Processing analysis...'}</span>
                  <span className="text-neonBlue font-bold">{progressPercent}%</span>
                </div>
                <div className="w-full bg-surface h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-neonBlue to-neonPink h-1.5 transition-all duration-200"
                    style={{ width: `${progressPercent}%` }}
                  />
                </div>
              </div>
            )}

            {/* Comprehensive Report Card (if generated) */}
            {comprehensiveReport && (
              <div className="bg-card border border-borderDark rounded-2xl p-6 shadow-xl space-y-4">
                <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 border-b border-borderDark pb-4">
                  <div>
                    <h3 className="text-base font-bold text-white">Correlated Forensic Summary</h3>
                    <p className="text-xs text-gray-400 mt-0.5">
                      {comprehensiveReport.summary.totalFindings} findings across {comprehensiveReport.summary.totalAnalyzersRun} analyzers in {comprehensiveReport.summary.executionTimeMs}ms.
                    </p>
                  </div>
                  {comprehensiveReport.allExtractedFiles.length > 0 && (
                    <button
                      onClick={() => downloadFilesAsZip(comprehensiveReport.allExtractedFiles, 'all_extracted_evidence.zip')}
                      className="px-4 py-2 bg-surface border border-borderDark text-white text-xs font-semibold rounded-lg hover:border-neonBlue flex items-center space-x-2 transition-all shadow"
                    >
                      <ArrowDownTrayIcon className="w-4 h-4 text-neonPink" />
                      <span>Download All Extracted Files ({comprehensiveReport.allExtractedFiles.length})</span>
                    </button>
                  )}
                </div>

                {comprehensiveReport.correlatedFindings.length > 0 ? (
                  <div className="space-y-2.5">
                    {comprehensiveReport.correlatedFindings.map((cf, idx) => (
                      <div key={idx} className="bg-surface p-3.5 rounded-xl border border-borderDark flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="text-xs font-bold text-neonPink">{cf.title}</span>
                            <span className="text-[10px] text-gray-400 font-mono">[{cf.sourceAnalyzers.join(', ')}]</span>
                          </div>
                          <p className="text-xs text-gray-300 mt-1">{cf.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-gray-400">Analysis completed. Select any tool below to inspect detailed outputs.</p>
                )}
              </div>
            )}

            {/* Analysis Tools Grid */}
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4 flex-1">
                  <h2 className="text-xl font-bold text-white whitespace-nowrap">Analysis Tools</h2>
                  <div className="h-[1px] bg-borderDark flex-1" />
                </div>
                <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-widest pl-4 hidden sm:inline">
                  CHOOSE A TOOL TO BEGIN
                </span>
              </div>

              {/* 3-Column Tool Cards Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                {TOOL_CARDS.map((tool) => (
                  <div
                    key={tool.id}
                    onClick={() => navigateToTool(tool.id)}
                    className="bg-card border border-borderDark rounded-2xl p-5 hover:border-gray-500 transition-all cursor-pointer group flex items-start space-x-4 shadow-lg hover:shadow-xl"
                  >
                    <div className={`p-3 rounded-xl border ${tool.iconBg} ${tool.iconColor} shrink-0`}>
                      <tool.icon className="h-6 w-6" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-bold text-white group-hover:text-neonPink transition-colors">
                          {tool.name}
                        </h3>
                        <ArrowRightIcon className="h-4 w-4 text-gray-400 group-hover:text-white group-hover:translate-x-1 transition-all" />
                      </div>
                      <p className="text-xs text-gray-400 mt-1.5 leading-relaxed">
                        {tool.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          /* VIEW: Active Tool Workspace View */
          <div className="space-y-8">
            {/* Top Workspace Header & Navigation */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-borderDark">
              <div className="flex items-center space-x-4">
                <button
                  onClick={() => navigateToTool(null)}
                  className="px-3.5 py-2 bg-card border border-borderDark rounded-xl text-xs font-semibold text-gray-300 hover:text-white hover:border-gray-500 transition-colors flex items-center space-x-2"
                >
                  <ArrowLeftIcon className="h-4 w-4" />
                  <span>All Tools</span>
                </button>

                <div>
                  <h2 className="text-2xl font-bold text-white tracking-tight">
                    {TOOL_CARDS.find(t => t.id === activeToolId)?.name}
                  </h2>
                  <p className="text-xs text-gray-400 mt-0.5">
                    {TOOL_CARDS.find(t => t.id === activeToolId)?.description}
                  </p>
                </div>
              </div>

              {/* Context File Info Badge */}
              {selectedFile && (
                <div className="flex items-center space-x-3 bg-card border border-borderDark px-3.5 py-2 rounded-xl text-xs">
                  {imagePreview ? (
                    <img src={imagePreview} alt="Preview" className="h-6 w-6 object-cover rounded-md" />
                  ) : (
                    <DocumentIcon className="h-5 w-5 text-neonBlue" />
                  )}
                  <span className="text-white font-medium truncate max-w-[180px]">{selectedFile.name}</span>
                  <span className="text-gray-400 text-[11px]">({(selectedFile.size / (1024 * 1024)).toFixed(2)} MB)</span>
                </div>
              )}
            </div>

            {/* Quick Tool Selector Tabs Bar */}
            <div className="flex overflow-x-auto gap-2 pb-2 scrollbar-none">
              {TOOL_CARDS.map(tool => (
                <button
                  key={tool.id}
                  onClick={() => navigateToTool(tool.id)}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition-all flex items-center space-x-2 ${
                    activeToolId === tool.id
                      ? 'bg-neonPink text-white shadow-md'
                      : 'bg-card text-gray-400 border border-borderDark hover:text-white hover:border-gray-600'
                  }`}
                >
                  <tool.icon className="h-4 w-4" />
                  <span>{tool.name}</span>
                </button>
              ))}
            </div>

            {/* No file prompt in tool view */}
            {!selectedFile ? (
              <div
                {...getRootProps()}
                className="border-2 border-dashed border-borderDark bg-card/40 rounded-2xl p-12 text-center cursor-pointer hover:border-gray-500"
              >
                <input {...getInputProps()} />
                <DocumentIcon className="h-12 w-12 text-gray-400 mx-auto mb-3" />
                <h3 className="text-base font-semibold text-white">Select a file to run {activeToolId}</h3>
                <p className="text-xs text-gray-400 mt-1">Drag and drop or click here to upload evidence</p>
              </div>
            ) : (
              /* Specific Tool Panel Output */
              <div className="space-y-6">
                {activeToolId === 'steghide' && (
                  <div className="space-y-5">
                    <div className="bg-card border border-borderDark rounded-2xl p-6 space-y-4">
                      <div className="flex flex-col sm:flex-row gap-4">
                        <div className="flex-1">
                          <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">
                            Passphrase (Optional):
                          </label>
                          <input
                            type="password"
                            value={steghidePassword}
                            onChange={(e) => setSteghidePassword(e.target.value)}
                            placeholder="Enter password if encrypted"
                            className="w-full bg-surface border border-borderDark text-white text-xs rounded-xl px-4 py-3 focus:outline-none focus:border-neonBlue"
                          />
                        </div>
                        <button
                          onClick={() => runAnalysisForTool('steghide')}
                          disabled={isAnalyzing}
                          className="sm:self-end px-6 py-3 bg-neonPink text-white text-xs font-bold rounded-xl hover:opacity-90 disabled:opacity-50 transition-all shadow-lg"
                        >
                          {isAnalyzing ? 'Extracting...' : 'Extract Data'}
                        </button>
                      </div>
                    </div>

                    {analysisResults['steghide'] && (
                      <div className="bg-card border border-borderDark rounded-2xl p-6 space-y-4">
                        <h3 className="text-sm font-bold text-white">Execution Status & Log</h3>
                        <pre className="text-xs font-mono text-gray-300 bg-surface p-4 rounded-xl border border-borderDark whitespace-pre-wrap overflow-x-auto">
                          {analysisResults['steghide'].stdout || 'No extraction log.'}
                        </pre>

                        {analysisResults['steghide'].files.length > 0 && (
                          <div className="pt-4 border-t border-borderDark space-y-3">
                            <div className="flex justify-between items-center">
                              <h4 className="text-xs font-bold text-white">Extracted Files ({analysisResults['steghide'].files.length})</h4>
                              <button
                                onClick={() => downloadFilesAsZip(analysisResults['steghide'].files, 'steghide_extracted.zip')}
                                className="px-3.5 py-1.5 bg-surface border border-borderDark text-white text-xs rounded-lg hover:border-neonBlue flex items-center space-x-1.5"
                              >
                                <ArrowDownTrayIcon className="h-4 w-4 text-neonPink" />
                                <span>Download ZIP</span>
                              </button>
                            </div>
                            {analysisResults['steghide'].files.map((f, i) => (
                              <div key={i} className="flex justify-between items-center bg-surface p-3 rounded-xl border border-borderDark">
                                <span className="text-xs font-medium text-white">{f.name} ({(f.size / 1024).toFixed(2)} KB)</span>
                                <button
                                  onClick={() => downloadExtractedFile(f)}
                                  className="text-xs px-3 py-1 bg-card hover:bg-gray-700 text-white rounded-lg border border-borderDark"
                                >
                                  Download
                                </button>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {activeToolId === 'binwalk' && (
                  <div className="space-y-5">
                    <div className="flex justify-between items-center bg-card border border-borderDark p-5 rounded-2xl">
                      <div>
                        <h3 className="text-sm font-bold text-white">Scan Signatures & Carve Archives</h3>
                        <p className="text-xs text-gray-400 mt-0.5">Identifies embedded headers and inflates compressed streams.</p>
                      </div>
                      <button
                        onClick={() => runAnalysisForTool('binwalk')}
                        disabled={isAnalyzing}
                        className="px-5 py-2.5 bg-blue-500 text-white text-xs font-bold rounded-xl hover:opacity-90 disabled:opacity-50"
                      >
                        {isAnalyzing ? 'Scanning...' : 'Re-scan Binwalk'}
                      </button>
                    </div>

                    {analysisResults['binwalk'] && (
                      <div className="space-y-5">
                        <div className="bg-card border border-borderDark rounded-2xl p-6">
                          <h3 className="text-sm font-bold text-white mb-4">Offset Table</h3>
                          {analysisResults['binwalk'].findings.length > 0 ? (
                            <div className="overflow-x-auto">
                              <table className="min-w-full divide-y divide-borderDark text-xs">
                                <thead>
                                  <tr>
                                    <th className="px-4 py-2.5 text-left font-medium text-gray-400">Offset (Hex)</th>
                                    <th className="px-4 py-2.5 text-left font-medium text-gray-400">Severity</th>
                                    <th className="px-4 py-2.5 text-left font-medium text-gray-400">Description</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-borderDark/60">
                                  {analysisResults['binwalk'].findings.map((f, i) => (
                                    <tr key={i} className="hover:bg-surface/50">
                                      <td className="px-4 py-2.5 font-mono text-neonBlue">0x{f.offset?.toString(16).toUpperCase()}</td>
                                      <td className="px-4 py-2.5">
                                        <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-blue-500/20 text-blue-300 uppercase">
                                          {f.severity || 'info'}
                                        </span>
                                      </td>
                                      <td className="px-4 py-2.5 text-gray-300">{f.description}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          ) : (
                            <p className="text-xs text-gray-400">No embedded container signatures discovered.</p>
                          )}
                        </div>

                        {analysisResults['binwalk'].files.length > 0 && (
                          <div className="bg-card border border-borderDark rounded-2xl p-6 space-y-3">
                            <div className="flex justify-between items-center">
                              <h3 className="text-sm font-bold text-white">Carved Files ({analysisResults['binwalk'].files.length})</h3>
                              <button
                                onClick={() => downloadFilesAsZip(analysisResults['binwalk'].files, 'binwalk_carved.zip')}
                                className="px-3.5 py-1.5 bg-surface border border-borderDark text-white text-xs rounded-lg hover:border-neonBlue flex items-center space-x-1.5"
                              >
                                <ArrowDownTrayIcon className="h-4 w-4 text-neonPink" />
                                <span>Download All as ZIP</span>
                              </button>
                            </div>
                            <div className="space-y-2 max-h-72 overflow-y-auto">
                              {analysisResults['binwalk'].files.map((f, i) => (
                                <div key={i} className="flex justify-between items-center bg-surface p-3 rounded-xl border border-borderDark">
                                  <div>
                                    <p className="text-xs font-semibold text-white">{f.name}</p>
                                    <p className="text-[11px] text-gray-400">{f.path} &bull; {(f.size / 1024).toFixed(2)} KB</p>
                                  </div>
                                  <button
                                    onClick={() => downloadExtractedFile(f)}
                                    className="text-xs px-3 py-1 bg-card hover:bg-gray-700 text-white rounded-lg border border-borderDark"
                                  >
                                    Download
                                  </button>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {activeToolId === 'strings' && (
                  <div className="space-y-5">
                    {analysisResults['strings'] && analysisResults['strings'].findings.length > 0 && (
                      <div className="bg-card border border-neonPink/30 rounded-2xl p-5 space-y-2">
                        <h3 className="text-xs font-bold text-neonPink uppercase tracking-wider">Uncovered Flags & Patterns</h3>
                        {analysisResults['strings'].findings.map((f, i) => (
                          <div key={i} className="text-xs font-mono text-emerald-400 bg-surface p-2.5 rounded-lg border border-emerald-500/20">
                            {f.description}
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="bg-card border border-borderDark rounded-2xl p-6 space-y-4">
                      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                        <h3 className="text-sm font-bold text-white">
                          Extracted Strings ({analysisResults['strings']?.data?.strings?.length || 0})
                        </h3>
                        {analysisResults['strings']?.data?.strings && (
                          <button
                            onClick={() => {
                              const textBlob = new Blob([analysisResults['strings'].data?.strings.join('\n')], { type: 'text/plain;charset=utf-8' });
                              const url = URL.createObjectURL(textBlob);
                              const a = document.createElement('a');
                              a.href = url;
                              a.download = 'extracted_strings.txt';
                              a.click();
                              URL.revokeObjectURL(url);
                            }}
                            className="px-3.5 py-1.5 bg-surface border border-borderDark text-white text-xs rounded-lg hover:border-neonBlue flex items-center space-x-1.5"
                          >
                            <ArrowDownTrayIcon className="h-4 w-4" />
                            <span>Download strings.txt</span>
                          </button>
                        )}
                      </div>

                      <div className="bg-surface rounded-xl p-3 font-mono text-xs text-gray-300 max-h-96 overflow-y-auto space-y-1 border border-borderDark">
                        {analysisResults['strings']?.data?.strings?.slice(0, 1000).map((str: string, i: number) => (
                          <div key={i} className="hover:bg-card px-2 py-0.5 rounded truncate">
                            <span className="text-gray-400 mr-2">{i + 1}</span>
                            {str}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {activeToolId === 'zsteg' && (
                  <div className="space-y-5">
                    <div className="bg-card border border-borderDark rounded-2xl p-6 space-y-3">
                      <h3 className="text-sm font-bold text-white">Zsteg Permutations Output</h3>
                      <pre className="bg-surface p-4 rounded-xl font-mono text-xs text-gray-300 whitespace-pre-wrap overflow-x-auto max-h-80 border border-borderDark">
                        {analysisResults['zsteg']?.stdout || 'Running permutation scanner...'}
                      </pre>
                    </div>

                    {analysisResults['zsteg']?.files && analysisResults['zsteg'].files.length > 0 && (
                      <div className="bg-card border border-borderDark rounded-2xl p-6 space-y-3">
                        <h3 className="text-sm font-bold text-white">Carved Channel Payloads</h3>
                        {analysisResults['zsteg'].files.map((f, i) => (
                          <div key={i} className="flex justify-between items-center bg-surface p-3 rounded-xl border border-borderDark">
                            <span className="text-xs font-medium text-white">{f.name} ({(f.size / 1024).toFixed(2)} KB)</span>
                            <button
                              onClick={() => downloadExtractedFile(f)}
                              className="text-xs px-3 py-1 bg-card hover:bg-gray-700 text-white rounded-lg border border-borderDark"
                            >
                              Download
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {activeToolId === 'rgb' && (
                  <RGBViewerDetail result={analysisResults['rgb']} />
                )}

                {activeToolId === 'metadata' && (
                  <div className="bg-card border border-borderDark rounded-2xl p-6 space-y-4">
                    <h3 className="text-sm font-bold text-white">Metadata Explorer</h3>
                    <MetadataTreeViewer data={analysisResults['metadata']?.data?.metadata || {}} />
                  </div>
                )}

                {activeToolId === 'entropy' && (
                  <div className="space-y-5">
                    <div className="bg-card border border-borderDark rounded-2xl p-6 flex justify-between items-center">
                      <div>
                        <h3 className="text-sm font-bold text-white">Global File Entropy</h3>
                        <p className="text-xs text-gray-400 mt-0.5">Calculated Shannon randomness across binary blocks.</p>
                      </div>
                      <div className="bg-surface px-4 py-2 rounded-xl border border-borderDark text-right">
                        <span className="text-lg font-bold font-mono text-white">
                          {analysisResults['entropy']?.data?.globalEntropy || '0.000'} / 8.0
                        </span>
                      </div>
                    </div>

                    {analysisResults['entropy']?.data?.blocks && (
                      <div className="bg-card border border-borderDark rounded-2xl p-6 space-y-3">
                        <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                          Block Entropy Distribution ({analysisResults['entropy'].data.blocks.length} blocks)
                        </h4>
                        <div className="h-44 bg-surface rounded-xl p-3 flex items-end gap-0.5 overflow-x-auto border border-borderDark">
                          {analysisResults['entropy'].data.blocks.map((b: any, idx: number) => {
                            const heightPercent = Math.max(5, Math.min(100, (b.entropy / 8.0) * 100));
                            const isHigh = b.entropy >= 7.5;
                            return (
                              <div
                                key={idx}
                                title={`${b.hexOffset}: ${b.entropy}`}
                                style={{ height: `${heightPercent}%` }}
                                className={`flex-1 min-w-[3px] rounded-t transition-all ${
                                  isHigh ? 'bg-neonPink' : 'bg-neonBlue/80 hover:bg-white'
                                }`}
                              />
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-surface border-t border-borderDark py-6 text-xs text-gray-400 mt-auto">
        <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row justify-between items-center gap-2">
          <span>&copy; 2026 The Hidden Bytes. All rights reserved.</span>
          <span>Built with WebAssembly &bull; Open Source &bull; v 2.0.0</span>
        </div>
      </footer>
    </div>
  );
}

/* -------------------------------------------------------------
 * RGB Viewer Detailed Sub-component
 * -----------------------------------------------------------*/

function RGBViewerDetail({ result }: { result?: AnalysisResult }) {
  const [activeMode, setActiveMode] = useState<'original' | 'red' | 'green' | 'blue' | 'inverse' | 'lsb_half' | 'bit_plane'>('original');
  const [selectedChannel, setSelectedChannel] = useState<'red' | 'green' | 'blue'>('red');
  const [selectedBit, setSelectedBit] = useState<number>(0);
  const [showRgbaTable, setShowRgbaTable] = useState<boolean>(false);

  const previews = result?.data?.previews;
  const dimensions = result?.data?.dimensions;
  const lsbDistribution = result?.data?.lsbDistribution;
  const rgbaSamples = result?.data?.rgbaSamples;

  let currentImageSrc = previews?.original;
  if (previews) {
    if (activeMode === 'bit_plane') {
      const bitKey = `bitplane_${selectedChannel}_${selectedBit}`;
      currentImageSrc = previews[bitKey] || previews.original;
    } else {
      currentImageSrc = previews[activeMode] || previews.original;
    }
  }

  return (
    <div className="space-y-6">
      {/* Primary Channel Filter Buttons */}
      <div className="flex flex-wrap gap-2 justify-center">
        {(['original', 'red', 'green', 'blue', 'inverse', 'lsb_half'] as const).map(mode => (
          <button
            key={mode}
            onClick={() => setActiveMode(mode)}
            className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all border ${
              activeMode === mode
                ? 'bg-neonPink text-white border-neonPink shadow-md'
                : 'bg-card text-gray-300 border-borderDark hover:border-gray-500'
            }`}
          >
            {mode === 'original' ? 'Original' : mode === 'lsb_half' ? 'LSB Half' : mode.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Render Image Canvas */}
      <div className="bg-surface border border-borderDark rounded-2xl p-6 flex flex-col items-center justify-center">
        {currentImageSrc ? (
          <img
            src={currentImageSrc}
            alt="Processed View"
            className="max-w-full max-h-[440px] object-contain rounded-xl shadow-xl border border-borderDark"
          />
        ) : (
          <p className="text-xs text-gray-400 py-16">Rendering image channels...</p>
        )}
        {dimensions && (
          <p className="text-[11px] text-gray-400 font-mono mt-3">
            Dimensions: {dimensions.width} x {dimensions.height} px
          </p>
        )}
      </div>

      {/* Interactive Bit-Plane Controller */}
      <div className="bg-card border border-borderDark rounded-2xl p-5 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-3 w-full md:w-auto">
          <span className="text-xs font-bold text-white uppercase tracking-wider">Channel:</span>
          <select
            value={selectedChannel}
            onChange={(e) => {
              setSelectedChannel(e.target.value as 'red' | 'green' | 'blue');
              setActiveMode('bit_plane');
            }}
            className="bg-surface border border-borderDark text-white text-xs rounded-xl px-3 py-2 font-medium focus:outline-none focus:border-neonBlue"
          >
            <option value="red">Red Channel</option>
            <option value="green">Green Channel</option>
            <option value="blue">Blue Channel</option>
          </select>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs font-bold text-white uppercase tracking-wider mr-1">Bit (0 = LSB, 7 = MSB):</span>
          <div className="flex space-x-1">
            {[0, 1, 2, 3, 4, 5, 6, 7].map((b) => (
              <button
                key={b}
                onClick={() => {
                  setSelectedBit(b);
                  setActiveMode('bit_plane');
                }}
                className={`w-8 h-8 rounded-lg text-xs font-bold transition-all border ${
                  activeMode === 'bit_plane' && selectedBit === b
                    ? 'bg-neonPink text-white border-neonPink shadow-md'
                    : 'bg-surface text-gray-300 border-borderDark hover:border-gray-500'
                }`}
              >
                {b}
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={() => setShowRgbaTable(!showRgbaTable)}
          className="px-4 py-2 bg-surface border border-borderDark text-white text-xs font-semibold rounded-xl hover:border-neonBlue transition-colors flex items-center space-x-1.5"
        >
          <TableCellsIcon className="h-4 w-4" />
          <span>{showRgbaTable ? 'Hide RGBA Table' : 'Show RGBA Table'}</span>
        </button>
      </div>

      {/* RGBA Sample Table */}
      {showRgbaTable && rgbaSamples && (
        <div className="bg-card border border-borderDark rounded-2xl p-5 space-y-2">
          <h4 className="text-xs font-bold text-neonBlue uppercase tracking-wider">
            Raw Pixel Values (First {rgbaSamples.length} pixels)
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 gap-2 text-[11px] font-mono max-h-60 overflow-y-auto">
            {rgbaSamples.map((p: any, idx: number) => (
              <div key={idx} className="bg-surface p-2 rounded-lg border border-borderDark text-gray-300">
                <span className="text-gray-400 block text-[10px]">[{p.x},{p.y}]</span>
                R:{p.r} G:{p.g} B:{p.b}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* LSB Statistical Ratio Badges */}
      {lsbDistribution && (
        <div className="bg-card border border-borderDark rounded-2xl p-5 space-y-3">
          <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider text-center">
            LSB Bit-0 Frequency Ratios
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-center">
            <div className="bg-surface p-3.5 rounded-xl border border-red-500/30">
              <span className="text-xs text-red-400 block font-medium">Red Channel</span>
              <span className="text-base font-bold font-mono text-white">{(lsbDistribution.red * 100).toFixed(1)}%</span>
            </div>
            <div className="bg-surface p-3.5 rounded-xl border border-green-500/30">
              <span className="text-xs text-green-400 block font-medium">Green Channel</span>
              <span className="text-base font-bold font-mono text-white">{(lsbDistribution.green * 100).toFixed(1)}%</span>
            </div>
            <div className="bg-surface p-3.5 rounded-xl border border-blue-500/30">
              <span className="text-xs text-blue-400 block font-medium">Blue Channel</span>
              <span className="text-base font-bold font-mono text-white">{(lsbDistribution.blue * 100).toFixed(1)}%</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------
 * Metadata Tree Sub-component (Open by default)
 * -----------------------------------------------------------*/

function MetadataTreeViewer({ data }: { data: Record<string, any> }) {
  const [openState, setOpenState] = useState<{ [key: string]: boolean }>({});
  const toggle = (key: string) => setOpenState(prev => ({ ...prev, [key]: prev[key] === false ? true : false }));

  if (!data || Object.keys(data).length === 0) {
    return <p className="text-xs text-gray-400">No metadata records found.</p>;
  }

  return (
    <ul className="space-y-3">
      {Object.entries(data).map(([key, value]) => {
        const isOpen = openState[key] !== false; // Open by default!
        return (
          <li key={key} className="bg-surface border border-borderDark rounded-xl p-4">
            {typeof value === 'object' && value !== null ? (
              <div>
                <button
                  onClick={() => toggle(key)}
                  className="text-sm font-bold text-neonBlue flex items-center space-x-2 hover:underline w-full text-left"
                >
                  <span className="text-xs">{isOpen ? '▼' : '▶'}</span>
                  <span>{key}</span>
                </button>

                {isOpen && (
                  <div className="mt-3 pt-3 border-t border-borderDark space-y-2">
                    {Object.entries(value).map(([subKey, subVal]) => (
                      <div key={subKey} className="flex flex-col sm:flex-row sm:justify-between py-1 text-xs border-b border-borderDark/40 last:border-0">
                        <span className="text-neonPink font-medium">{subKey}:</span>
                        <span className="text-gray-300 font-mono break-all sm:text-right">{String(subVal)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="flex flex-col sm:flex-row sm:justify-between text-xs">
                <span className="text-neonPink font-medium">{key}:</span>
                <span className="text-gray-300 font-mono break-all sm:text-right">{String(value)}</span>
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}