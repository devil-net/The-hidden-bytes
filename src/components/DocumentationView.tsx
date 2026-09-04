import React, { useState } from 'react';
import {
  ArrowLeftIcon,
  BookOpenIcon,
  PhotoIcon,
  DocumentIcon,
  CodeBracketIcon,
  CircleStackIcon,
  ChartBarIcon,
  EyeIcon,
  Squares2X2Icon,
  SparklesIcon,
  CpuChipIcon
} from '@heroicons/react/24/outline';

interface Chapter {
  id: string;
  title: string;
  category: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  iconColor: string;
  content: {
    summary: string;
    howItWorks: string[];
    useCases: string[];
    technicalDetails: string;
    cliAnalogy?: string;
  };
}

const CHAPTERS: Chapter[] = [
  {
    id: 'architecture',
    title: 'Architecture & Engine',
    category: 'V2 System Core',
    icon: CpuChipIcon,
    iconColor: 'text-neonBlue',
    content: {
      summary: 'The Hidden Bytes V2 is engineered as a zero-backend forensic workbench executing 100% inside your browser RAM via WebAssembly and Web Workers.',
      howItWorks: [
        'Isolated Memory Runtime: Files never leave your browser device. Everything is processed in transient WebAssembly virtual memory (MEMFS).',
        'Web Worker Sandbox: Analysis runs off the main browser thread to guarantee a responsive 60 FPS user interface during intensive stream carving.',
        'Zero Data Retention: Once the tab is closed or a file is cleared, all raw buffers are garbage collected immediately.'
      ],
      useCases: [
        'Security researchers analyzing sensitive or proprietary firmware without uploading to external cloud endpoints.',
        'CTF competitors working offline or requiring instant client-side file decompression and password cracking.',
        'Forensic investigators triaging suspect images and document attachments with zero network footprint.'
      ],
      technicalDetails: 'Employs a custom Virtual File System (VFS) with quota management (50MB carving limits, recursion ceilings) and Web Crypto API SHA-256 validation.'
    }
  },
  {
    id: 'steghide',
    title: 'Steghide Engine',
    category: 'Carrier Steganography',
    icon: PhotoIcon,
    iconColor: 'text-neonPink',
    content: {
      summary: 'Steghide is a steganography program capable of hiding data in various kinds of image and audio files (JPEG, BMP, WAV, AU).',
      howItWorks: [
        'Color & Frequency Domain Embedding: Modifies Discrete Cosine Transform (DCT) coefficients in JPEG images and sample values in BMP/WAV audio.',
        'Passphrase Authentication: Hashes the provided passphrase using MHash algorithms to derive encryption keys (Rijndael-128, Blowfish, 3DES).',
        'Graph-Theoretic Selection: Uses a pseudo-random permutation algorithm to distribute secret bits across carrier frequencies without introducing visible artifacts.'
      ],
      useCases: [
        'Uncovering password-protected hidden messages and embedded archives in CTF challenges.',
        'Extracting sensitive text payloads from carrier JPEG photographs and WAV audio recordings.',
        'Validating passphrase dictionary attacks locally without server rate limits.'
      ],
      technicalDetails: 'Supports passphrase verification, decompression of Rijndael-128 cipher blocks, and automatic extraction to downloadable memory buffers.',
      cliAnalogy: 'steghide extract -sf <carrier_file> -p <passphrase>'
    }
  },
  {
    id: 'binwalk',
    title: 'Binwalk & Firmware Carver',
    category: 'Firmware & Streams',
    icon: DocumentIcon,
    iconColor: 'text-blue-400',
    content: {
      summary: 'Binwalk searches binary images and firmware blobs for embedded file headers, compressed containers, and executable segments.',
      howItWorks: [
        'Magic Signature Database: Scans every byte offset against a curated database of file signatures (PKZip, GZIP, 7-Zip, ELF, PE, SQLite, ZLIB).',
        'Boundary Detection: Calculates the start offset and container length to isolate individual sub-components.',
        'In-Memory Stream Inflation: Automatically unzips PKZip archives and decompresses raw zlib/gzip streams directly in browser RAM.'
      ],
      useCases: [
        'Carving embedded ZIP archives hidden inside PNG or JPEG images.',
        'Extracting compressed filesystem images (SquashFS, CramFS) from router firmware blobs.',
        'Identifying polyglot files (files that are simultaneously valid in multiple formats, e.g. GIF-ZIP polyglots).'
      ],
      technicalDetails: 'Integrates fflate decompressors for lossless stream recovery, computing cryptographic SHA-256 hashes for all carved artifacts.',
      cliAnalogy: 'binwalk -e -M <target_binary>'
    }
  },
  {
    id: 'strings',
    title: 'Strings & Pattern Scanner',
    category: 'Binary Analysis',
    icon: CodeBracketIcon,
    iconColor: 'text-emerald-400',
    content: {
      summary: 'Extracts printable character sequences from binary files with automated pattern detection for CTF flags, URLs, and encoded tokens.',
      howItWorks: [
        'Multi-Encoding Byte Scanner: Streams through raw Uint8Array buffers detecting contiguous printable sequences (ASCII, UTF-8, UTF-16LE, UTF-16BE).',
        'Configurable Length Thresholds: Filters noise by requiring minimum character lengths (default: 4 chars, matching GNU strings -n 4).',
        'Automated Pattern Heuristics: Scans matches against regex patterns for CTF flags (flag{...}, ctf{...}), URLs, and Base64 encoded payload blocks.'
      ],
      useCases: [
        'Discovering hardcoded credentials, API keys, and usernames compiled inside binaries.',
        'Instant flag discovery in CTF reverse engineering and steganography tasks.',
        'Auditing compiled binaries for debugging symbols and internal IP addresses.'
      ],
      technicalDetails: 'Processes multi-megabyte binaries in sub-50ms with zero memory duplication using streaming typed array slices.',
      cliAnalogy: 'strings -n 4 -t x <binary_file> | grep -i flag'
    }
  },
  {
    id: 'zsteg',
    title: 'Zsteg Stego Engine',
    category: 'PNG & BMP Forensics',
    icon: Squares2X2Icon,
    iconColor: 'text-purple-400',
    content: {
      summary: 'Zsteg is a specialized steganography engine that detects hidden data in PNG and BMP images across various color channels and bit planes.',
      howItWorks: [
        '15 Channel Permutations: Iterates across individual and combined channels (Red, Green, Blue, Alpha) in LSB and MSB bit orders.',
        'Pixel Ordering Traversal: Tests both standard row-first (xy) and column-first (yx) pixel traversal orders.',
        'Payload Heuristic Verification: Evaluates extracted bitstreams for printable ASCII text, valid magic headers, and compressed ZLIB streams.'
      ],
      useCases: [
        'Solving PNG steganography challenges where text or files are hidden in specific color channel bit-planes.',
        'Detecting alpha channel steganography (subtle transparency perturbations).',
        'Extracting hidden zlib streams embedded across multi-channel RGB LSB planes.'
      ],
      technicalDetails: 'Compatible engine testing permutations: b1,r,lsb,xy | b1,g,lsb,xy | b1,b,lsb,xy | b1,rgb,lsb,xy | b1,rgba,lsb,xy | b2,... | b4,...',
      cliAnalogy: 'zsteg -a <image.png>'
    }
  },
  {
    id: 'rgb',
    title: 'Bit Panels & RGB Viewer',
    category: 'Visual Steganalysis',
    icon: EyeIcon,
    iconColor: 'text-neonBlue',
    content: {
      summary: 'Isolates individual color channels and bit planes (0 through 7) to visually expose hidden steganographic layers.',
      howItWorks: [
        'Channel Separation: Decomposes RGBA pixels into isolated Red, Green, Blue, and Inverted components.',
        '8-Bit Plane Matrix: Slices pixels at bit positions 0 (Least Significant Bit) through 7 (Most Significant Bit) and boosts contrast to 255 for visual inspection.',
        'LSB Statistical Distribution: Calculates the 0/1 bit frequency ratio across channels (near-uniform 50.0% ratio suggests LSB substitution steganography).'
      ],
      useCases: [
        'Visually inspecting watermark patterns or hidden QR codes embedded in lower bit planes.',
        'Detecting LSB Half steganography (where data is stored in the lower 4 bits).',
        'Inspecting raw RGBA pixel arrays for localized steganographic noise.'
      ],
      technicalDetails: 'Utilizes browser OffscreenCanvas and direct Uint8ClampedArray pixel buffer manipulation for real-time channel rendering.'
    }
  },
  {
    id: 'metadata',
    title: 'Metadata Explorer',
    category: 'Header Forensics',
    icon: CircleStackIcon,
    iconColor: 'text-amber-400',
    content: {
      summary: 'Extracts header metadata dictionaries, camera models, GPS geolocation coordinates, and container properties across media files.',
      howItWorks: [
        'Expanded Tag Reading: Parses EXIF, XMP, IPTC, and ICC profiles from JPEG, TIFF, PNG, and WebP images.',
        'Geospatial Mapping: Extracts GPS Latitude and Longitude coordinates embedded by mobile cameras.',
        'Container Dictionaries: Scans PDF document dictionaries (/Title, /Author, /CreationDate) and ID3 audio metadata (Title, Artist, Album).'
      ],
      useCases: [
        'Extracting author names, software signatures (e.g. Photoshop timestamps), and device serial numbers.',
        'Uncovering secret flags hidden in image comment chunks (tEXt/zTXt) or PDF creator fields.',
        'Geolocating photo evidence using embedded GPS metadata.'
      ],
      technicalDetails: 'Zero-network local parsing with expanded dictionary tree rendering, open by default for immediate inspection.'
    }
  },
  {
    id: 'entropy',
    title: 'Shannon Entropy Mapping',
    category: 'Statistical Analysis',
    icon: ChartBarIcon,
    iconColor: 'text-yellow-400',
    content: {
      summary: 'Measures the degree of randomness across chunked binary blocks to distinguish plaintext, compressed data, and encrypted carriers.',
      howItWorks: [
        'Shannon Entropy Formula: Computes H(X) = -sum(P(x) * log2(P(x))) over byte frequencies across adaptive 256-4096 byte blocks.',
        'Entropy Scale (0.0 to 8.0): Plaintext typically scores 3.5 - 5.0; compiled code scores 5.5 - 6.8; encrypted/compressed blocks score 7.5 - 8.0.',
        'Region Boundary Detection: Highlights high-entropy contiguous zones indicating appended encrypted archives or secret payload containers.'
      ],
      useCases: [
        'Detecting encrypted payloads appended after image termination markers (e.g. after JPEG EOI or PNG IEND).',
        'Differentiating packed vs unpacked executable sections.',
        'Mapping unknown binary blobs to identify filesystem structures and data boundaries.'
      ],
      technicalDetails: 'Renders an interactive block entropy distribution graph mapping offset vs randomness with threshold indicators.'
    }
  },
  {
    id: 'roadmap',
    title: 'Upcoming Tools in V2.x',
    category: 'Future Roadmap',
    icon: SparklesIcon,
    iconColor: 'text-neonPink',
    content: {
      summary: 'The Hidden Bytes V2 roadmap introduces specialized digital forensics engines currently in active engineering.',
      howItWorks: [
        'Audio Steganography Suite: Automated LSB, parity, and echo hiding analysis across WAV, MP3, and FLAC audio files with spectrogram rendering.',
        'PDF Obfuscation & Stream Scraper: Decompresses incremental PDF revisions, hidden JavaScript streams, and disguised attachment dictionaries.',
        'Neural Steganalysis (ONNX-WASM): Client-side convolutional neural networks trained to detect spatial Jsteg, F5, and OutGuess perturbations.',
        'Memory Dump Carver: Forensic scanner carving active network sockets, injected DLLs, and credential artifacts from raw memory dumps.'
      ],
      useCases: [
        'Expanded coverage for audio, document, and memory forensics without requiring server installations.',
        'Next-generation machine learning detection for high-order steganographic algorithms.'
      ],
      technicalDetails: 'All upcoming modules will adhere to the V2 contract: 100% browser-local execution, zero network telemetry, and modular analyzer integration.'
    }
  }
];

export function DocumentationView({ onBack }: { onBack: () => void }) {
  const [selectedChapterId, setSelectedChapterId] = useState<string>('architecture');
  const activeChapter = CHAPTERS.find(c => c.id === selectedChapterId) || CHAPTERS[0];

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Top Header & Back Button */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-borderDark">
        <div className="flex items-center space-x-4">
          <button
            onClick={onBack}
            className="px-3.5 py-2 bg-card border border-borderDark rounded-xl text-xs font-semibold text-gray-300 hover:text-white hover:border-gray-500 transition-colors flex items-center space-x-2 shadow-sm"
          >
            <ArrowLeftIcon className="h-4 w-4" />
            <span>Back to Workbench</span>
          </button>

          <div>
            <h2 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
              <BookOpenIcon className="h-6 w-6 text-neonPink inline" />
              <span>Technical Manual & Tool Documentation</span>
            </h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Comprehensive reference guide for steganography, firmware carving, and upcoming V2.x engines.
            </p>
          </div>
        </div>

        <div className="text-xs font-mono text-gray-400 bg-surface px-3 py-1.5 rounded-lg border border-borderDark self-start sm:self-auto">
          The Hidden Bytes &bull; Handbook V2.0
        </div>
      </div>

      {/* Book Layout: Sidebar on Left + Reading Content on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Table of Contents / Chapter Index */}
        <div className="lg:col-span-4 bg-card border border-borderDark rounded-2xl p-4 space-y-1.5 shadow-xl">
          <div className="text-[10px] font-bold text-gray-400 uppercase tracking-widest px-3 py-2">
            Chapters & Modules
          </div>

          {CHAPTERS.map(chapter => (
            <button
              key={chapter.id}
              onClick={() => setSelectedChapterId(chapter.id)}
              className={`w-full flex items-center space-x-3 px-3.5 py-3 rounded-xl text-xs font-semibold transition-all text-left ${
                selectedChapterId === chapter.id
                  ? 'bg-surface text-white border border-borderDark shadow-md'
                  : 'text-gray-400 hover:text-white hover:bg-surface/50'
              }`}
            >
              <chapter.icon className={`h-5 w-5 ${chapter.iconColor} shrink-0`} />
              <div className="flex-1 min-w-0">
                <p className="truncate text-white">{chapter.title}</p>
                <p className="text-[10px] text-gray-400 font-normal truncate mt-0.5">{chapter.category}</p>
              </div>
            </button>
          ))}
        </div>

        {/* Chapter Reading Pane (Book Page) */}
        <div className="lg:col-span-8 bg-card border border-borderDark rounded-2xl p-6 sm:p-8 shadow-2xl space-y-8">
          {/* Chapter Header */}
          <div className="border-b border-borderDark pb-6 space-y-2">
            <div className="flex items-center space-x-2.5">
              <div className="p-2.5 rounded-xl bg-surface border border-borderDark">
                <activeChapter.icon className={`h-6 w-6 ${activeChapter.iconColor}`} />
              </div>
              <div>
                <span className="text-[11px] font-mono font-bold text-neonPink uppercase tracking-wider">
                  {activeChapter.category}
                </span>
                <h3 className="text-2xl font-black text-white tracking-tight">
                  {activeChapter.title}
                </h3>
              </div>
            </div>

            <p className="text-sm text-gray-300 leading-relaxed pt-2">
              {activeChapter.content.summary}
            </p>
          </div>

          {/* How It Works Section */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <span className="w-1.5 h-1.5 rounded-full bg-neonBlue" />
              <span>How It Works & Underlying Principles</span>
            </h4>
            <div className="space-y-2.5 pl-3 border-l border-borderDark">
              {activeChapter.content.howItWorks.map((point, idx) => (
                <div key={idx} className="bg-surface/70 p-3.5 rounded-xl border border-borderDark text-xs text-gray-300 leading-relaxed">
                  {point}
                </div>
              ))}
            </div>
          </div>

          {/* Practical Use Cases */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <span className="w-1.5 h-1.5 rounded-full bg-neonPink" />
              <span>Forensic & CTF Use Cases</span>
            </h4>
            <div className="grid grid-cols-1 gap-2 pl-3 border-l border-borderDark">
              {activeChapter.content.useCases.map((useCase, idx) => (
                <div key={idx} className="bg-surface/70 p-3 rounded-xl border border-borderDark text-xs text-gray-300 flex items-start space-x-2.5">
                  <span className="text-neonPink font-bold mt-0.5">&bull;</span>
                  <span>{useCase}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Technical Engine Details */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Engine Implementation</span>
            </h4>
            <div className="bg-surface p-4 rounded-xl border border-borderDark text-xs text-gray-300 font-mono leading-relaxed">
              {activeChapter.content.technicalDetails}
            </div>
          </div>

          {/* CLI Reference (if applicable) */}
          {activeChapter.content.cliAnalogy && (
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">
                Linux CLI Reference
              </h4>
              <div className="bg-black/60 p-3.5 rounded-xl border border-borderDark text-xs font-mono text-neonBlue flex items-center justify-between">
                <span>{activeChapter.content.cliAnalogy}</span>
                <span className="text-[10px] text-gray-400">Emulated in V2 RAM</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
