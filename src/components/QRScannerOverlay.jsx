import React, { useRef, useEffect, useState } from 'react';
import jsQR from 'jsqr';
import { X, ScanLine, CameraOff } from 'lucide-react';

const QRScannerOverlay = ({ onScan, onClose }) => {
    const videoRef = useRef(null);
    const canvasRef = useRef(null);
    const rafRef = useRef(null);
    const streamRef = useRef(null);
    const scannedRef = useRef(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        let alive = true;

        const tick = () => {
            if (!alive || scannedRef.current) return;
            const video = videoRef.current;
            const canvas = canvasRef.current;
            if (video && canvas && video.readyState === video.HAVE_ENOUGH_DATA) {
                canvas.width = video.videoWidth;
                canvas.height = video.videoHeight;
                const ctx = canvas.getContext('2d', { willReadFrequently: true });
                ctx.drawImage(video, 0, 0);
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height, {
                    inversionAttempts: 'dontInvert',
                });
                if (code?.data) {
                    scannedRef.current = true;
                    onScan(code.data);
                    return;
                }
            }
            rafRef.current = requestAnimationFrame(tick);
        };

        const start = async () => {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 } },
                });
                if (!alive) { stream.getTracks().forEach(t => t.stop()); return; }
                streamRef.current = stream;
                if (videoRef.current) {
                    videoRef.current.srcObject = stream;
                    videoRef.current.onloadedmetadata = () => {
                        videoRef.current?.play();
                        rafRef.current = requestAnimationFrame(tick);
                    };
                }
            } catch (err) {
                if (alive) setError(err.message || 'Camera access denied');
            }
        };

        start();

        return () => {
            alive = false;
            cancelAnimationFrame(rafRef.current);
            streamRef.current?.getTracks().forEach(t => t.stop());
        };
    }, [onScan]);

    return (
        <div className="fixed inset-0 z-[200] bg-black flex flex-col">
            <div className="flex items-center justify-between p-4 text-white">
                <div className="flex items-center gap-2">
                    <ScanLine size={18} />
                    <span className="text-[15px] font-medium">Scan a code</span>
                </div>
                <button
                    onClick={onClose}
                    className="p-2 rounded-full bg-white/10 hover:bg-white/20 transition-colors"
                    aria-label="Close scanner"
                >
                    <X size={20} />
                </button>
            </div>

            <div className="flex-1 flex flex-col items-center justify-center px-6">
                {error ? (
                    <div className="flex flex-col items-center gap-3 text-center text-white">
                        <CameraOff size={40} className="text-white/40" />
                        <p className="font-medium">Camera unavailable</p>
                        <p className="text-sm text-white/50">{error}</p>
                        <button
                            onClick={onClose}
                            className="mt-2 px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-sm transition-colors"
                        >
                            Close
                        </button>
                    </div>
                ) : (
                    <div className="w-full max-w-sm rounded-2xl overflow-hidden shadow-2xl relative">
                        <video
                            ref={videoRef}
                            className="w-full block"
                            playsInline
                            muted
                        />
                        <canvas ref={canvasRef} className="hidden" />
                        {/* Viewfinder overlay */}
                        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                            <div className="w-48 h-48 border-2 border-white/60 rounded-xl" />
                        </div>
                    </div>
                )}
                <p className="text-white/60 text-sm mt-6 text-center">
                    Point at the QR code on the login page
                </p>
            </div>
        </div>
    );
};

export default QRScannerOverlay;
