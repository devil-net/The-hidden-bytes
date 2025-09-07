import { useState, useEffect } from 'react'
import { Tab } from '@headlessui/react'
import { useDropzone } from 'react-dropzone'
import { PhotoIcon, DocumentIcon, CodeBracketIcon, CircleStackIcon, ArrowDownTrayIcon, EyeIcon, ShareIcon, FilmIcon, MusicalNoteIcon, DocumentTextIcon, ArchiveBoxIcon } from '@heroicons/react/24/outline'

interface Tool {
  name: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  color: string;
}

interface AnalysisResult {
  success: boolean;
  output?: string;
  error?: string;
  strings?: string[];
  dimensions?: {
    width: number;
    height: number;
  };
  channels?: {
    red: number[];
    green: number[];
    blue: number[];
  };
  metadata?: Record<string, any>;
  analysis?: Array<{
    offset: number;
    type: string;
    description: string;
  }>;
  extracted_files?: Array<{
    name: string;
    size: number;
    path: string;
  }>;
  extraction_output?: string;
  extraction_error?: string;
  download_id?: string;
}

// Header Component
const Header = () => {
  const handleShare = async () => {
    if (navigator.share) {
      try {
        await navigator.share({
          title: 'the hidden bytes',
          text: 'Check out this amazing steganography analysis tool!',
          url: window.location.href,
        });
      } catch (error) {
        console.log('Error sharing:', error);
      }
    } else {
      // Fallback for browsers that don't support Web Share API
      navigator.clipboard.writeText(window.location.href);
      alert('Link copied to clipboard!');
    }
  };

  return (
    <header className="bg-slate/80 backdrop-blur-md border-b border-gray-700 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Left side - Title with Logo */}
          <div className="flex items-center space-x-3">
            <img src="/logo.svg" alt="Logo" className="h-8 w-8" />
            <h1 className="text-2xl font-bold text-white">
              the hidden <span className="text-neonPink">bytes</span>
            </h1>
          </div>

          {/* Right side - Actions */}
          <div className="flex items-center space-x-4">
            <button
              onClick={handleShare}
              className="p-2 text-gray-300 hover:text-neonBlue transition-colors"
              title="Share"
            >
              <ShareIcon className="h-6 w-6" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};

// Animated Heading Component
const AnimatedHeading = () => {
  const [showBytes, setShowBytes] = useState(false);

  useEffect(() => {
    // Show "bytes" after 2 seconds
    const timer = setTimeout(() => {
      setShowBytes(true);
    }, 2000);

    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="text-center mb-8">
      <div className="flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-4 mb-6 sm:mb-8">
        <img src="/logo.svg" alt="Logo" className="h-12 w-12 sm:h-16 sm:w-16 md:h-20 md:w-20 lg:h-24 lg:w-24" />
        <h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl xl:text-6xl font-bold text-white text-center sm:text-left">
          <span className="text-white">the hidden</span>
          <span className={`transition-all duration-1000 ${showBytes ? 'opacity-100' : 'opacity-0'}`}>
            <span className="text-neonPink"> bytes</span>
          </span>
        </h1>
      </div>
    </div>
  );
};

function classNames(...classes: string[]) {
  return classes.filter(Boolean).join(' ')
}

// Function to get appropriate icon and color for file type
const getFileIcon = (file: File | null) => {
  if (!file) return { icon: PhotoIcon, color: 'text-gray-400' }
  
  const type = file.type.toLowerCase()
  const extension = file.name.split('.').pop()?.toLowerCase()
  
  if (type.startsWith('image/')) {
    return { icon: PhotoIcon, color: 'text-neonBlue' }
  } else if (type.startsWith('video/')) {
    return { icon: FilmIcon, color: 'text-neonPink' }
  } else if (type.startsWith('audio/')) {
    return { icon: MusicalNoteIcon, color: 'text-green-400' }
  } else if (type === 'application/pdf' || extension === 'pdf') {
    return { icon: DocumentTextIcon, color: 'text-red-400' }
  } else if (type.includes('zip') || type.includes('archive') || ['zip', 'rar', '7z'].includes(extension || '')) {
    return { icon: ArchiveBoxIcon, color: 'text-yellow-400' }
  } else if (type.startsWith('text/') || ['txt', 'log', 'csv', 'json', 'xml', 'html', 'css', 'js'].includes(extension || '')) {
    return { icon: CodeBracketIcon, color: 'text-purple-400' }
  } else {
    return { icon: DocumentIcon, color: 'text-gray-400' }
  }
}

const tools: Tool[] = [
  { name: 'Steghide', icon: PhotoIcon, color: 'text-neonBlue' },
  { name: 'Binwalk', icon: DocumentIcon, color: 'text-neonPink' },
  { name: 'Strings', icon: CodeBracketIcon, color: 'text-neonBlue' },
  { name: 'Zsteg', icon: PhotoIcon, color: 'text-green-400' },
  { name: 'RGB Viewer', icon: PhotoIcon, color: 'text-neonPink' },
  { name: 'Metadata', icon: CircleStackIcon, color: 'text-neonBlue' },
]

const BinwalkPanel = ({ 
  result, 
  selectedFile, 
  setAnalysisResults 
}: { 
  result: AnalysisResult;
  selectedFile: File | null;
  setAnalysisResults: React.Dispatch<React.SetStateAction<Record<string, AnalysisResult>>>;
}) => {
  const [isExtracting, setIsExtracting] = useState(false);

  const handleExtractAndDownload = async () => {
    if (!selectedFile) return;
    setIsExtracting(true);
    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('extract', 'true');

    try {
      const response = await fetch(`${API_BASE_URL}/binwalk`, {
        method: 'POST',
        body: formData,
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.success === false) {
        console.error('Extraction failed:', data.error || data.extraction_error);
        alert(`Extraction failed: ${data.error || data.extraction_error || 'Unknown error'}`);
      } else {
        setAnalysisResults(prev => ({ ...prev, 'Binwalk': data }));
        
        // If extraction was successful and we have a download_id, trigger download
        if (data.download_id && data.extracted_files && data.extracted_files.length > 0) {
          const downloadUrl = `${API_BASE_URL}/download/${data.download_id}`;
          const link = document.createElement('a');
          link.href = downloadUrl;
          link.download = `binwalk_extracted_${data.download_id.substring(0, 8)}.zip`;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
        }
      }
    } catch (error) {
      console.error('Error extracting files:', error);
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error occurred'}`);
    } finally {
      setIsExtracting(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Analysis Results */}
      <div className="bg-dark/50 rounded-lg p-4">
        <h3 className="text-lg font-semibold mb-2 text-white">Analysis Results</h3>
        {result.analysis && result.analysis.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-700">
              <thead>
                <tr>
                  <th className="px-4 py-2 text-left text-sm font-medium text-white">Offset</th>
                  <th className="px-4 py-2 text-left text-sm font-medium text-white">Type</th>
                  <th className="px-4 py-2 text-left text-sm font-medium text-white">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {result.analysis.map((item, index) => (
                  <tr key={index}>
                    <td className="px-4 py-2 text-sm text-gray-300">0x{item.offset.toString(16)}</td>
                    <td className="px-4 py-2 text-sm text-gray-300">{item.type}</td>
                    <td className="px-4 py-2 text-sm text-gray-300">{item.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-400">No analysis results available</p>
        )}
      </div>

      {/* Extraction Section */}
      <div className="bg-dark/50 rounded-lg p-4">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-semibold text-white">Extracted Files</h3>
          <button
            onClick={handleExtractAndDownload}
            disabled={isExtracting}
            className="px-6 py-3 bg-gradient-to-r from-neonBlue to-neonPink text-white rounded-lg hover:from-neonBlue/80 hover:to-neonPink/80 disabled:opacity-50 transition-all duration-300 flex items-center gap-2 shadow-lg hover:shadow-xl transform hover:scale-105"
          >
            <ArrowDownTrayIcon className="h-5 w-5" />
            {isExtracting ? 'Extracting & Preparing Download...' : 'Download ZIP'}
          </button>
        </div>
        
        {result.extracted_files && result.extracted_files.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-700">
              <thead>
                <tr>
                  <th className="px-4 py-2 text-left text-sm font-medium text-white">Name</th>
                  <th className="px-4 py-2 text-left text-sm font-medium text-white">Size</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {result.extracted_files.map((file, index) => (
                  <tr key={index}>
                    <td className="px-4 py-2 text-sm text-gray-300">{file.name}</td>
                    <td className="px-4 py-2 text-sm text-gray-300">
                      {(file.size / 1024).toFixed(2)} KB
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-400">
            {isExtracting ? 'Extracting files...' : 'No files extracted yet'}
          </p>
        )}
      </div>

      {/* Extraction Output */}
      {result.extraction_output && (
        <div className="bg-dark/50 rounded-lg p-4">
          <h3 className="text-lg font-semibold mb-2 text-white">Extraction Output</h3>
          <pre className="text-sm text-gray-300 whitespace-pre-wrap">
            {result.extraction_output}
          </pre>
        </div>
      )}

      {/* Error Messages */}
      {(result.error || result.extraction_error) && (
        <div className="bg-red-900/20 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-red-400 mb-2">Errors</h3>
          {result.error && (
            <pre className="text-sm text-red-300 whitespace-pre-wrap">{result.error}</pre>
          )}
          {result.extraction_error && (
            <pre className="text-sm text-red-300 whitespace-pre-wrap">{result.extraction_error}</pre>
          )}
        </div>
      )}
    </div>
  );
};

const RGBViewerPanel = ({ selectedFile }: { selectedFile: File | null }) => {
  const [mode, setMode] = useState<'original'|'red'|'green'|'blue'|'inverse'|'lsb_half'|'bit_plane'>('original');
  const [imageBase64, setImageBase64] = useState<string | null>(null);
  const [rgbaValues, setRgbaValues] = useState<any[] | null>(null);
  const [showRgba, setShowRgba] = useState(false);
  const [bit, setBit] = useState(0);
  const [channel, setChannel] = useState<'red'|'green'|'blue'>('red');
  const [isLoading, setIsLoading] = useState(false);
  const [dimensions, setDimensions] = useState<{width:number, height:number}|null>(null);

  const fetchImage = async (modeOverride?: string, bitOverride?: number, channelOverride?: string) => {
    if (!selectedFile) return;
    setIsLoading(true);
    setShowRgba(false);
    const formData = new FormData();
    formData.append('file', selectedFile);
            let url = `${API_BASE_URL}/rgb?mode=${modeOverride||mode}`;
    if ((modeOverride||mode) === 'bit_plane') {
      url += `&bit=${bitOverride ?? bit}&channel=${channelOverride ?? channel}`;
    }
    try {
      const response = await fetch(url, { method: 'POST', body: formData });
      const data = await response.json();
      setDimensions(data.dimensions);
      setImageBase64(data.image_base64 || null);
      setRgbaValues(data.rgba_values || null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => { if (selectedFile) fetchImage('original'); }, [selectedFile]);
  useEffect(() => { if (selectedFile) fetchImage(); }, [mode, bit, channel]);

  const handleMode = (m: typeof mode) => { setMode(m); };
  const handleShowRgba = async () => {
    if (!selectedFile) return;
    setIsLoading(true);
    setShowRgba(true);
    const formData = new FormData();
    formData.append('file', selectedFile);
        const url = `${API_BASE_URL}/rgb?mode=rgba_values`;
    const response = await fetch(url, { method: 'POST', body: formData });
    const data = await response.json();
    setRgbaValues(data.rgba_values || null);
    setIsLoading(false);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-3 justify-center">
        <button className="px-4 py-2 bg-gradient-to-r from-neonBlue to-neonPink text-white rounded-lg hover:from-neonBlue/80 hover:to-neonPink/80 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105" onClick={() => handleMode('original')}>
          <EyeIcon className="h-4 w-4 inline mr-2" />
          Reset
        </button>
        <button className="px-4 py-2 bg-gradient-to-r from-red-500 to-red-600 text-white rounded-lg hover:from-red-600 hover:to-red-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105" onClick={() => handleMode('red')}>
          Full Red
        </button>
        <button className="px-4 py-2 bg-gradient-to-r from-green-500 to-green-600 text-white rounded-lg hover:from-green-600 hover:to-green-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105" onClick={() => handleMode('green')}>
          Full Green
        </button>
        <button className="px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg hover:from-blue-600 hover:to-blue-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105" onClick={() => handleMode('blue')}>
          Full Blue
        </button>
        <button className="px-4 py-2 bg-gradient-to-r from-gray-500 to-gray-600 text-white rounded-lg hover:from-gray-600 hover:to-gray-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105" onClick={() => handleMode('inverse')}>
          Inverse (RGB)
        </button>
        <button className="px-4 py-2 bg-gradient-to-r from-pink-500 to-pink-600 text-white rounded-lg hover:from-pink-600 hover:to-pink-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105" onClick={() => handleMode('lsb_half')}>
          LSB Half
        </button>
      </div>
      <div className="flex flex-col items-center">
        {isLoading ? (
          <div className="text-center"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-neonBlue mx-auto"></div><p className="mt-2 text-sm text-gray-400">Loading...</p></div>
        ) : imageBase64 ? (
          <img src={`data:image/png;base64,${imageBase64}`} alt="Processed" className="max-w-full max-h-96 rounded shadow" style={{background:'#222'}} />
        ) : (
          <p className="text-gray-400">No image to display</p>
        )}
        {dimensions && <p className="mt-2 text-xs text-gray-400">Dimensions: {dimensions.width} x {dimensions.height}</p>}
      </div>
      <div className="flex flex-wrap gap-3 justify-center">
        <button className="px-4 py-2 bg-gradient-to-r from-gray-600 to-gray-700 text-white rounded-lg hover:from-gray-700 hover:to-gray-800 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105" onClick={handleShowRgba}>
          Show RGBA Values
        </button>
        <div className="flex flex-col sm:flex-row items-center gap-3 bg-dark/50 rounded-lg p-3">
          <span className="text-white font-medium">Browse Bit Planes:</span>
          <select value={channel} onChange={e => setChannel(e.target.value as 'red'|'green'|'blue')} className="bg-slate text-white rounded-lg px-3 py-2 border border-gray-600 focus:border-neonBlue focus:outline-none">
            <option value="red">Red</option>
            <option value="green">Green</option>
            <option value="blue">Blue</option>
          </select>
          <div className="flex items-center gap-2">
            <span className="text-white font-medium">Bit:</span>
            <div className="flex gap-1">
              {[0, 1, 2, 3, 4, 5, 6, 7].map((bitNum) => (
                <button
                  key={bitNum}
                  onClick={() => { setBit(bitNum); setMode('bit_plane'); fetchImage('bit_plane', bitNum, channel); }}
                  className={`w-8 h-8 rounded text-sm font-bold transition-all duration-300 ${
                    bit === bitNum 
                      ? 'bg-neonPink text-white shadow-lg' 
                      : 'bg-gray-600 text-gray-300 hover:bg-gray-500 hover:text-white'
                  }`}
                >
                  {bitNum}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
      {showRgba && rgbaValues && (
        <div className="max-h-64 overflow-auto bg-dark/80 rounded p-2 mt-2">
          <h4 className="text-sm text-neonBlue mb-2">RGBA Values (showing first 1000 pixels):</h4>
          <pre className="text-xs text-gray-300">{JSON.stringify(rgbaValues.slice(0,1000), null, 2)}{rgbaValues.length > 1000 ? '\n... (truncated)' : ''}</pre>
        </div>
      )}
    </div>
  );
};

const MetadataTree = ({ data }: { data: Record<string, any> }) => {
  const [open, setOpen] = useState<{ [key: string]: boolean }>({});
  const toggle = (key: string) => setOpen(o => ({ ...o, [key]: !o[key] }));
  if (!data) return <div className="text-gray-400">No metadata found.</div>;
  return (
    <ul className="text-xs text-gray-200">
      {Object.entries(data).map(([key, value]) => (
        <li key={key} className="mb-1">
          {typeof value === 'object' && value !== null ? (
            <>
              <button className="text-neonBlue font-bold" onClick={() => toggle(key)}>
                {open[key] ? '▼' : '▶'} {key}
              </button>
              {open[key] && <div className="ml-4 border-l border-neonBlue pl-2"><MetadataTree data={value} /></div>}
            </>
          ) : (
            <span><span className="text-neonPink">{key}:</span> {String(value)}</span>
          )}
        </li>
      ))}
    </ul>
  );
};

const SteghidePanel = ({ 
  result, 
  selectedFile, 
  password, 
  setPassword, 
  onAnalyze, 
  isAnalyzing 
}: { 
  result: AnalysisResult;
  selectedFile: File | null;
  password: string;
  setPassword: (password: string) => void;
  onAnalyze: () => void;
  isAnalyzing: boolean;
}) => {
  return (
    <div className="space-y-4">
      {/* Password Input */}
      <div className="bg-dark/50 rounded-lg p-4">
        <label htmlFor="steghide-password" className="block text-sm font-medium text-white mb-2">
          Password (optional)
        </label>
        <div className="flex gap-3">
          <input
            id="steghide-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter steghide password"
            className="flex-1 bg-slate text-white border border-gray-600 rounded-lg px-3 py-2 focus:border-neonBlue focus:outline-none"
          />
          <button
            onClick={onAnalyze}
            disabled={!selectedFile || isAnalyzing}
            className="px-6 py-2 bg-gradient-to-r from-neonBlue to-neonPink text-white rounded-lg hover:from-neonBlue/80 hover:to-neonPink/80 disabled:opacity-50 transition-all duration-300 flex items-center gap-2 shadow-lg hover:shadow-xl transform hover:scale-105"
          >
            {isAnalyzing ? 'Analyzing...' : 'Extract'}
          </button>
        </div>
        <p className="text-xs text-gray-400 mt-2">
          Leave empty if no password is required
        </p>
      </div>

      {/* Results */}
      {result && (
        <div className="bg-dark/50 rounded-lg p-4">
          <h3 className="text-lg font-semibold mb-2 text-white">Results</h3>
          {result.success ? (
            <div className="text-green-400">
              <p className="font-medium">✓ Extraction successful!</p>
              {result.output && (
                <pre className="text-sm text-gray-300 whitespace-pre-wrap mt-2 bg-slate/50 p-3 rounded">
                  {result.output}
                </pre>
              )}
              {result.download_id && result.extracted_files && result.extracted_files.length > 0 && (
                <div className="mt-4">
                  <button
                    onClick={() => {
                      const downloadUrl = `${API_BASE_URL}/download/${result.download_id}`;
                      const link = document.createElement('a');
                      link.href = downloadUrl;
                      link.download = `steghide_extracted_${result.download_id?.substring(0, 8)}.zip`;
                      document.body.appendChild(link);
                      link.click();
                      document.body.removeChild(link);
                    }}
                    className="px-4 py-2 bg-gradient-to-r from-green-500 to-green-600 text-white rounded-lg hover:from-green-600 hover:to-green-700 transition-all duration-300 flex items-center gap-2 shadow-lg hover:shadow-xl transform hover:scale-105"
                  >
                    <ArrowDownTrayIcon className="h-4 w-4" />
                    Download Extracted Files
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="text-red-400">
              <p className="font-medium">✗ Extraction failed</p>
              {result.error && (
                <pre className="text-sm text-red-300 whitespace-pre-wrap mt-2 bg-red-900/20 p-3 rounded">
                  {result.error}
                </pre>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const TOOL_INFO = {
  Steghide: {
    title: 'Steghide',
    description: 'Steghide is a steganography tool that embeds a file (like a flag) inside another file, typically an image or audio file. In CTF, you\'ll often encounter a file that seems normal but might contain a hidden message. Steghide can be used to extract this hidden data if you have the correct passphrase. The command steghide extract -sf <filename> will attempt to extract any hidden file. If the file is password-protected, you\'ll need to provide the password with the -p option.'
  },
  Binwalk: {
    title: 'Binwalk',
    description: 'Binwalk is a firmware analysis tool but is widely used in CTF for identifying hidden files or data embedded within other files. It scans a file for known file signatures, which are specific byte sequences that identify the type of a file. For example, it can detect a ZIP file embedded at the end of a PNG image. The command binwalk <filename> will show all the embedded files. You can also use the -e option to automatically extract them, e.g., binwalk -e <filename>.'
  },
  Strings: {
    title: 'Strings',
    description: 'The strings command is a simple but powerful tool that extracts printable character sequences from a binary file. It\'s useful for finding plain text data, such as usernames, passwords, URLs, or even the flag itself, that might be hidden within an executable or other binary file. A common use case is piping the output to grep to search for specific keywords, like strings <filename> | grep \'flag\'.'
  },
  Zsteg: {
    title: 'Zsteg',
    description: 'Zsteg is a Ruby gem specifically designed for detecting steganographic data hidden in PNG and BMP images. It automatically checks for data hidden in various bit planes and color channels using different steganographic techniques. Unlike other tools that require you to specify parameters, zsteg tries multiple detection methods automatically, making it extremely useful for CTF challenges. It can detect LSB steganography, bit-plane analysis, and other hiding techniques. Simply run zsteg <filename.png> to see if any hidden data is found.'
  },
  'RGB Viewer': {
    title: 'Bit Panels',
    description: 'While not a standard tool, "bit panels" in a CTF context often refers to analyzing the least significant bits (LSB) of an image to find hidden data. In LSB steganography, the last bit of each color value in an image pixel is modified to store data, which is usually imperceptible to the human eye. CTF players use specialized scripts or tools like zsteg to visualize or extract this hidden information. This technique is common in steganography challenges.'
  },
  Metadata: {
    title: 'Metadata',
    description: 'Metadata is "data about data." In CTF, it refers to information stored within a file that isn\'t part of the main content. For images, this could include the camera model, date and time, GPS coordinates, or the software used to create it. You can use tools like exiftool or strings to view this information. A CTF flag could be hidden in a camera\'s owner field, in the GPS coordinates, or even in a comment field. Always check the metadata of any file you\'re given.'
  }
};

// Tool Information Section Component
const ToolInformationSection = () => {
  const toolEntries = Object.entries(TOOL_INFO);
  
  return (
    <div className="mt-8 sm:mt-12 lg:mt-16 mb-8">
      <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold text-white text-center mb-6 sm:mb-8">
        Tool <span className="text-neonPink">Information</span>
      </h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
        {toolEntries.map(([key, info]) => (
          <div
            key={key}
            className="bg-slate border border-gray-600 rounded-lg p-4 sm:p-6 transition-all duration-300 hover:border-neonBlue hover:shadow-lg hover:shadow-neonBlue/20 hover:scale-105 cursor-pointer group"
          >
            <h3 className="text-lg sm:text-xl font-bold text-neonBlue mb-3 group-hover:text-neonPink transition-colors duration-300">
              {info.title}
            </h3>
            <p className="text-sm sm:text-base text-gray-300 leading-relaxed group-hover:text-white transition-colors duration-300">
              {info.description}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};

// Footer Component
const Footer = () => {
  return (
    <footer className="bg-slate/80 border-t border-gray-700 mt-auto">
      <div className="max-w-[1600px] mx-auto px-2 sm:px-4 md:px-6 lg:px-8 xl:px-12 2xl:px-16 py-6">
        <div className="flex flex-col sm:flex-row justify-between items-center space-y-4 sm:space-y-0">
          <div className="text-center sm:text-left">
            <p className="text-gray-400 text-sm">
              © 2025 the hidden <span className="text-neonPink">bytes</span>. Built for CTF enthusiasts.
            </p>
          </div>
          <div className="flex items-center space-x-6">
            <a
              href="https://github.com/devil-net"
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-400 hover:text-neonBlue transition-colors duration-300 transform hover:scale-110"
              title="GitHub Profile"
            >
              <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
            </a>
            <a
              href="https://x.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-400 hover:text-neonBlue transition-colors duration-300 transform hover:scale-110"
              title="X (Twitter)"
            >
              <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
              </svg>
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
};




// Use environment variable for API URL
const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://the-hidden-bytes-production-7988.up.railway.app';

export default function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [imagePreview, setImagePreview] = useState<string | null>(null)
  const [analysisResults, setAnalysisResults] = useState<Record<string, AnalysisResult>>({})
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [steghidePassword, setSteghidePassword] = useState('')

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
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
    maxSize: 100 * 1024 * 1024, // 100MB
    onDrop: (acceptedFiles: File[]) => {
      const file = acceptedFiles[0]
      if (file) {
        setSelectedFile(file)
        
        // Clear previous preview and create new one only for images
        setImagePreview(null)
        
        // Only create preview for image files
        if (file.type.startsWith('image/')) {
          const reader = new FileReader()
          reader.onload = (e) => {
            const result = e.target?.result
            if (result && typeof result === 'string') {
              setImagePreview(result)
            }
          }
          reader.onerror = () => {
            console.error('Error reading file for preview')
            setImagePreview(null)
          }
          reader.readAsDataURL(file)
        }
      } else {
        setSelectedFile(null)
        setImagePreview(null)
      }
    }
  })

  const analyzeImage = async (tool: string) => {
    if (!selectedFile) return

    setIsAnalyzing(true)
    const formData = new FormData()
    formData.append('file', selectedFile)
    
    // Add password for steghide
    if (tool === 'Steghide') {
      formData.append('password', steghidePassword)
    }

    // Map tool names to API endpoints
    const toolEndpoints: Record<string, string> = {
      'Steghide': 'steghide',
      'Binwalk': 'binwalk',
      'Strings': 'strings',
      'Zsteg': 'zsteg',
      'RGB Viewer': 'rgb',
      'Metadata': 'metadata'
    }

    const endpoint = toolEndpoints[tool] || tool.toLowerCase()

    try {
            const response = await fetch(`${API_BASE_URL}/${endpoint}`, {
        method: 'POST',
        body: formData,
      })
      const data = await response.json()
      setAnalysisResults(prev => ({ ...prev, [tool]: data }))
    } catch (error) {
      console.error(`Error analyzing with ${tool}:`, error)
    } finally {
      setIsAnalyzing(false)
    }
  }


  return (
    <div className="min-h-screen bg-dark text-white flex flex-col">
      <Header />
      <div className="flex-1 w-full px-2 sm:px-4 md:px-6 lg:px-8 xl:px-12 2xl:px-16 py-4 sm:py-6 lg:py-8">
        <div className="max-w-[1600px] mx-auto">
          <AnimatedHeading />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6 lg:gap-8">
            {/* File Upload Section */}
            <div className="bg-slate rounded-lg p-4 sm:p-6">
              <div
                {...getRootProps()}
                className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors
                  ${isDragActive ? 'border-neonBlue bg-slate/50' : 'border-gray-600 hover:border-neonPink'}`}
              >
                <input {...getInputProps()} />
                {selectedFile ? (
                  <div className="space-y-4">
                    {imagePreview ? (
                      <img 
                        src={imagePreview} 
                        alt="Preview" 
                        className="mx-auto max-h-48 max-w-full rounded-lg shadow-lg border border-gray-600"
                      />
                    ) : (
                      <div className="mx-auto max-h-48 max-w-full rounded-lg shadow-lg border border-gray-600 bg-gray-800 flex items-center justify-center p-8">
                        <div className="text-center">
                          {(() => {
                            const { icon: FileIcon, color } = getFileIcon(selectedFile)
                            return (
                              <>
                                <FileIcon className={`mx-auto h-16 w-16 ${color} mb-4`} />
                                <p className="text-sm text-gray-400">
                                  {selectedFile.type.startsWith('image/') ? 'Loading preview...' : 'File ready for analysis'}
                                </p>
                              </>
                            )
                          })()}
                        </div>
                      </div>
                    )}
                    <div className="text-center">
                      <p className="text-sm text-neonBlue font-medium">
                        {selectedFile.name}
                      </p>
                      <p className="text-xs text-gray-400 mt-1">
                        {(selectedFile.size / 1024 / 1024).toFixed(2)} MB • {selectedFile.type || 'Unknown type'}
                      </p>
                      <p className="text-xs text-gray-500 mt-2">
                        Click or drag to change file
                      </p>
                    </div>
                  </div>
                ) : (
                  <>
                    <PhotoIcon className="mx-auto h-12 w-12 text-gray-400" />
                    <p className="mt-2 text-sm text-gray-400">
                      {isDragActive
                        ? "Drop the file here..."
                        : "Drag 'n' drop any file here, or click to select"}
                    </p>
                    <p className="mt-1 text-xs text-gray-500">
                      Supports images, videos, audio, PDFs, archives, and more
                    </p>
                  </>
                )}
              </div>
            </div>

            {/* Analysis Tools Section */}
            <div className="bg-slate rounded-lg p-4 sm:p-6">
              <Tab.Group>
                <Tab.List className="flex flex-wrap space-x-1 rounded-xl bg-dark/50 p-1">
                  {tools.map((tool) => (
                    <Tab
                      key={tool.name}
                      className={({ selected }: { selected: boolean }) =>
                        classNames(
                          'flex-1 rounded-lg py-2.5 text-sm font-medium leading-5 min-w-0',
                          'ring-white ring-opacity-60 ring-offset-2 ring-offset-neonBlue focus:outline-none focus:ring-2',
                          selected
                            ? 'bg-slate text-white shadow'
                            : 'text-gray-400 hover:bg-slate/[0.12] hover:text-white'
                        )
                      }
                      onClick={() => analyzeImage(tool.name)}
                    >
                      <div className="flex items-center justify-center space-x-2">
                        <tool.icon className={`h-5 w-5 ${tool.color}`} />
                        <span className="truncate">{tool.name}</span>
                      </div>
                    </Tab>
                  ))}
                </Tab.List>
                <Tab.Panels className="mt-4">
                  {tools.map((tool) => (
                    <Tab.Panel key={tool.name} className="rounded-xl bg-dark/50 p-4">
                      {isAnalyzing ? (
                        <div className="text-center">
                          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-neonBlue mx-auto"></div>
                          <p className="mt-2 text-sm text-gray-400">Analyzing...</p>
                        </div>
                      ) : tool.name === 'RGB Viewer' ? (
                        <RGBViewerPanel selectedFile={selectedFile} />
                      ) : tool.name === 'Binwalk' ? (
                        <BinwalkPanel
                          result={analysisResults[tool.name]}
                          selectedFile={selectedFile}
                          setAnalysisResults={setAnalysisResults}
                        />
                      ) : tool.name === 'Steghide' ? (
                        <SteghidePanel
                          result={analysisResults[tool.name]}
                          selectedFile={selectedFile}
                          password={steghidePassword}
                          setPassword={setSteghidePassword}
                          onAnalyze={() => analyzeImage('Steghide')}
                          isAnalyzing={isAnalyzing}
                        />
                      ) : tool.name === 'Metadata' && analysisResults[tool.name]?.metadata ? (
                        <MetadataTree data={analysisResults[tool.name].metadata || {}} />
                      ) : tool.name === 'Metadata' && analysisResults[tool.name]?.error ? (
                        <div className="text-red-400">{analysisResults[tool.name].error}</div>
                      ) : tool.name === 'Strings' && analysisResults[tool.name]?.strings ? (
                        <div className="bg-dark/50 rounded-lg p-4">
                          <h3 className="text-lg font-semibold mb-2 text-white">Extracted Strings</h3>
                          <div className="max-h-96 overflow-auto">
                            <pre className="text-sm text-gray-300 whitespace-pre-wrap">
                              {analysisResults[tool.name].strings?.join('\n')}
                            </pre>
                          </div>
                        </div>
                      ) : tool.name === 'Strings' && analysisResults[tool.name]?.error ? (
                        <div className="text-red-400">{analysisResults[tool.name].error}</div>
                      ) : tool.name === 'Zsteg' && analysisResults[tool.name] ? (
                        <div className="bg-dark/50 rounded-lg p-4">
                          <h3 className="text-lg font-semibold mb-2 text-white">Zsteg Analysis Results</h3>
                          {analysisResults[tool.name].success ? (
                            analysisResults[tool.name].output ? (
                              <div className="max-h-96 overflow-auto">
                                <pre className="text-sm text-gray-300 whitespace-pre-wrap bg-slate/50 p-3 rounded">
                                  {analysisResults[tool.name].output}
                                </pre>
                              </div>
                            ) : (
                              <p className="text-gray-400">No hidden data detected in this image.</p>
                            )
                          ) : (
                            <div className="text-red-400">
                              <p className="font-medium">Analysis failed</p>
                              {analysisResults[tool.name].error && (
                                <pre className="text-sm text-red-300 whitespace-pre-wrap mt-2 bg-red-900/20 p-3 rounded">
                                  {analysisResults[tool.name].error}
                                </pre>
                              )}
                            </div>
                          )}
                        </div>
                      ) : analysisResults[tool.name] ? (
                        <pre className="text-sm overflow-auto max-h-96">
                          {JSON.stringify(analysisResults[tool.name], null, 2)}
                        </pre>
                      ) : !selectedFile ? (
                        <p className="text-center text-gray-400">Please select a file first</p>
                      ) : (
                        <p className="text-center text-gray-400">Click to analyze with {tool.name}</p>
                      )}
                    </Tab.Panel>
                  ))}
                </Tab.Panels>
              </Tab.Group>
            </div>
          </div>
        
          {/* Tool Information Section */}
          <ToolInformationSection />
        </div>
      </div>
      
      {/* Footer */}
      <Footer />
    </div>
  )
} 