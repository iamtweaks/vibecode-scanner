"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import {
	Shield,
	Zap,
	Globe,
	Github,
	Terminal,
	Lock,
	ArrowRight,
	FileCode,
	Sparkles,
	AlertTriangle,
	CheckCircle,
	Bug,
	BarChart3,
	Star,
	FileText,
	Copy,
	Check,
	Users,
	X,
	ChevronRight,
} from "lucide-react";
import { downloadPDF } from "@/lib/pdf";
import type { Severity, Finding } from "@/lib/types";

type ScanType = "github" | "website";

interface ScanResult {
	scanId: string;
	type: ScanType;
	targetUrl: string;
	status: "pending" | "running" | "completed" | "failed";
	findings: Finding[];
	severityCounts: Record<Severity, number>;
	scannedAt: string;
	scanDuration?: number;
}

const SEVERITY_STYLES: Record<
	Severity,
	{ bg: string; text: string; border: string; dot: string }
> = {
	critical: {
		bg: "bg-kanagawa-red/10",
		text: "text-kanagawa-red",
		border: "border-kanagawa-red/30",
		dot: "bg-kanagawa-red",
	},
	high: {
		bg: "bg-kanagawa-peach/10",
		text: "text-kanagawa-peach",
		border: "border-kanagawa-peach/30",
		dot: "bg-kanagawa-peach",
	},
	medium: {
		bg: "bg-kanagawa-yellow/10",
		text: "text-kanagawa-yellow",
		border: "border-kanagawa-yellow/30",
		dot: "bg-kanagawa-yellow",
	},
	low: {
		bg: "bg-kanagawa-teal/10",
		text: "text-kanagawa-teal",
		border: "border-kanagawa-teal/30",
		dot: "bg-kanagawa-teal",
	},
	info: {
		bg: "bg-kanagawa-surface",
		text: "text-kanagawa-fgDim",
		border: "border-kanagawa-border",
		dot: "bg-kanagawa-fgDim",
	},
};

function SeverityBadge({ severity }: { severity: Severity }) {
	const style = SEVERITY_STYLES[severity];
	return (
		<span
			className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${style.bg} ${style.text} border`}
		>
			<span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
			{severity.charAt(0).toUpperCase() + severity.slice(1)}
		</span>
	);
}

function scoreTier(score: number): { label: string; color: string; bg: string; border: string } {
	if (score >= 80) return { label: "Critical", color: "text-kanagawa-red", bg: "bg-kanagawa-red/15", border: "border-kanagawa-red/40" };
	if (score >= 60) return { label: "High", color: "text-kanagawa-orange", bg: "bg-kanagawa-orange/15", border: "border-kanagawa-orange/40" };
	if (score >= 40) return { label: "Medium", color: "text-kanagawa-yellow", bg: "bg-kanagawa-yellow/15", border: "border-kanagawa-yellow/40" };
	if (score >= 20) return { label: "Low", color: "text-kanagawa-blue", bg: "bg-kanagawa-blue/15", border: "border-kanagawa-blue/40" };
	return { label: "Info", color: "text-kanagawa-fgDim", bg: "bg-kanagawa-fgDim/10", border: "border-kanagawa-border" };
}

function scoreBadge(score: number): string {
	return `${score}/100`;
}

function AnimatedCounter({
	end,
	duration = 2000,
}: {
	end: number;
	duration?: number;
}) {
	const [count, setCount] = useState(0);
	const [hasAnimated, setHasAnimated] = useState(false);
	const ref = useRef<HTMLSpanElement>(null);

	useEffect(() => {
		const observer = new IntersectionObserver(
			([entry]) => {
				if (entry.isIntersecting && !hasAnimated) {
					setHasAnimated(true);
					let start = 0;
					const increment = end / (duration / 16);
					const timer = setInterval(() => {
						start += increment;
						if (start >= end) {
							setCount(end);
							clearInterval(timer);
						} else {
							setCount(Math.floor(start));
						}
					}, 16);
				}
			},
			{ threshold: 0.5 },
		);
		if (ref.current) observer.observe(ref.current);
		return () => observer.disconnect();
	}, [end, duration, hasAnimated]);

	return <span ref={ref}>{count.toLocaleString()}</span>;
}

function FadeIn({
	children,
	delay = 0,
	className = "",
}: {
	children: React.ReactNode;
	delay?: number;
	className?: string;
}) {
	const [visible, setVisible] = useState(false);
	const ref = useRef<HTMLDivElement>(null);

	useEffect(() => {
		const observer = new IntersectionObserver(
			([entry]) => {
				if (entry.isIntersecting) {
					setTimeout(() => setVisible(true), delay);
					observer.disconnect();
				}
			},
			{ threshold: 0.1 },
		);
		if (ref.current) observer.observe(ref.current);
		return () => observer.disconnect();
	}, [delay]);

	return (
		<div
			ref={ref}
			className={`transition-all duration-700 ease-out ${className}`}
			style={{
				opacity: visible ? 1 : 0,
				transform: visible
					? "translateY(0) scale(1)"
					: "translateY(20px) scale(0.95)",
				filter: visible ? "blur(0)" : "blur(4px)",
			}}
		>
			{children}
		</div>
	);
}

function seededUnit(seed: number): number {
	const value = Math.sin(seed * 12.9898) * 43758.5453;
	return value - Math.floor(value);
}

function FloatingParticles() {
	const particles = Array.from({ length: 20 }, (_, i) => ({
		id: i,
		left: `${seededUnit(i + 1) * 100}%`,
		size: seededUnit(i + 21) * 4 + 2,
		delay: seededUnit(i + 41) * 8,
		duration: seededUnit(i + 61) * 6 + 8,
		color: seededUnit(i + 81) > 0.5 ? "#34d399" : "#22c55e",
	}));

	return (
		<div className="particles-container">
			{particles.map((p) => (
				<div
					key={p.id}
					className="particle"
					style={{
						left: p.left,
						width: p.size,
						height: p.size,
						color: p.color,
						animationDelay: `${p.delay}s`,
						animationDuration: `${p.duration}s`,
					}}
				/>
			))}
		</div>
	);
}

function HeroGlints() {
	const glints = Array.from({ length: 8 }, (_, i) => ({
		id: i,
		left: `${15 + seededUnit(i + 101) * 70}%`,
		top: `${20 + seededUnit(i + 121) * 60}%`,
		delay: seededUnit(i + 141) * 6,
		size: seededUnit(i + 161) * 3 + 2,
	}));

	return (
		<>
			{glints.map((g) => (
				<div
					key={g.id}
					className="glint"
					style={{
						left: g.left,
						top: g.top,
						animationDelay: `${g.delay}s`,
						width: g.size,
						height: g.size,
					}}
				/>
			))}
		</>
	);
}

function Header() {
	return (
		<header className="fixed top-0 left-0 right-0 z-50 bg-kanagawa-bg/80 backdrop-blur-lg border-b border-kanagawa-border/50">
			<div className="max-w-5xl mx-auto px-4 md:px-6 py-3 md:py-4 flex items-center justify-between">
				<a href="#" className="flex items-center gap-2">
					<div className="w-8 h-8 rounded-lg bg-gradient-to-br from-kanagawa-accent to-kanagawa-violet flex items-center justify-center">
						<Shield className="w-5 h-5 text-kanagawa-bg" />
					</div>
					<span className="font-semibold text-base md:text-lg tracking-tight text-kanagawa-fg">
						VibeChecker
					</span>
				</a>
				<nav className="flex items-center gap-4 md:gap-6 text-sm">
					<a
						href="https://github.com/iamtweaks/vibe-checker"
						target="_blank"
						rel="noopener noreferrer"
						className="text-kanagawa-fgMuted hover:text-kanagawa-fg transition-colors"
					>
						<Github className="w-5 h-5" />
					</a>
				</nav>
			</div>
		</header>
	);
}

function Hero() {
	return (
		<section className="pt-28 pb-16 text-center bg-gradient-to-b from-kanagawa-bg via-kanagawa-surface to-kanagawa-bg overflow-hidden">
			<div className="absolute inset-0 overflow-hidden pointer-events-none">
				<div className="absolute top-20 left-1/4 w-72 h-72 bg-kanagawa-accent rounded-full blur-3xl opacity-20" />
				<div className="absolute top-40 right-1/4 w-96 h-96 bg-kanagawa-violet rounded-full blur-3xl opacity-15" />
				<FloatingParticles />
				<HeroGlints />
			</div>
			<div className="relative max-w-3xl mx-auto px-6">
				<FadeIn>
					<div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-kanagawa-surface border border-kanagawa-accent/30 text-sm text-kanagawa-accent mb-8 shimmer">
						<Sparkles className="w-4 h-4" />
						<span>Free • No Signup • Results in Seconds</span>
					</div>
				</FadeIn>
				<FadeIn delay={100}>
					<h1 className="text-4xl md:text-5xl lg:text-6xl font-semibold tracking-tight text-kanagawa-fg mb-6">
						The Security Scanner
						<br />
						<span className="bg-gradient-to-r from-kanagawa-accent to-kanagawa-teal bg-clip-text text-transparent">
							Built for Vibe-Coded Apps
						</span>
					</h1>
				</FadeIn>
				<FadeIn delay={200}>
					<p className="text-lg text-kanagawa-fgMuted mb-8 max-w-2xl mx-auto leading-relaxed">
						If you built your app with{" "}
						<strong>Lovable, Bolt, Cursor, Replit,</strong> or{" "}
						<strong>Google AI Studio</strong>, VibeCheck finds the security
						vulnerabilities that AI code generators commonly introduce.
					</p>
				</FadeIn>
				<FadeIn delay={300}>
					<div className="flex flex-col sm:flex-row items-center justify-center gap-4">
						<a
							href="#scanner"
							className="group btn-glow inline-flex items-center gap-2 px-6 py-3.5 rounded-xl bg-kanagawa-accent text-kanagawa-bg font-medium hover:bg-kanagawa-accentSoft transition-all hover:gap-3 border-glow"
						>
							Scan Your App Free
							<ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
						</a>
						<a
							href="https://github.com/iamtweaks/vibe-checker"
							target="_blank"
							rel="noopener noreferrer"
							className="inline-flex items-center gap-2 px-6 py-3.5 rounded-xl border border-kanagawa-border text-kanagawa-fgMuted font-medium hover:bg-kanagawa-surface hover:border-kanagawa-accent/40 transition-all hover:shadow-md"
						>
							<Github className="w-4 h-4" />
							View on GitHub
						</a>
					</div>
				</FadeIn>
			</div>
		</section>
	);
}

interface StatsData {
	uniqueSites: number;
	totalScans: number;
	uniqueVulnerabilities: number;
	totalVulnerabilities: number;
}

function Stats({
	statsData,
	loaded,
}: {
	statsData: StatsData;
	loaded: boolean;
}) {
	const stats = [
		{
			value: loaded ? statsData.uniqueSites : 0,
			label: "Apps Scanned",
			suffix: "",
		},
		{
			value: loaded ? statsData.uniqueVulnerabilities : 0,
			label: "Vulnerabilities Found",
			suffix: "+",
		},
		{ value: 65, label: "Security Checks", suffix: "+" },
		{ value: 100, label: "Free Forever", suffix: "%" },
	];

	return (
		<section id="stats" className="py-16 bg-kanagawa-surface">
			<div className="max-w-5xl mx-auto px-4 md:px-6">
				<div className="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-8">
					{stats.map((stat, i) => (
						<FadeIn key={i} delay={i * 100}>
							<div className="text-center stat-card p-3 md:p-4 rounded-xl bg-kanagawa-bg/40">
								<div className="text-2xl md:text-3xl lg:text-4xl font-bold text-kanagawa-fg mb-1">
									<AnimatedCounter end={stat.value} />
									<span className="text-kanagawa-accent">{stat.suffix}</span>
								</div>
								<div className="text-xs md:text-sm text-kanagawa-fgDim">
									{stat.label}
								</div>
							</div>
						</FadeIn>
					))}
				</div>
			</div>
		</section>
	);
}

function RealityCheck() {
	return (
		<section className="py-12 md:py-20 bg-gradient-to-b from-kanagawa-bg to-kanagawa-surface">
			<div className="max-w-5xl mx-auto px-4 md:px-6">
				<FadeIn>
					<div className="text-center mb-8 md:mb-12">
						<div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-kanagawa-red/10 border border-kanagawa-red/30 text-xs md:text-sm text-kanagawa-red mb-3 md:mb-4">
							<AlertTriangle className="w-4 h-4" />
							<span>The Data Is Alarming</span>
						</div>
						<h2 className="text-2xl md:text-3xl font-semibold tracking-tight text-kanagawa-fg mb-3">
							What the Research Says
						</h2>
						<p className="text-kanagawa-fgMuted max-w-2xl mx-auto text-xs md:text-sm">
							Escape.tech scanned 5,600 vibe-coded apps and found over 2,000
							vulnerabilities and 400 exposed secrets. Tenzai tested 15 apps
							built with 5 AI coding tools and found 69 vulnerabilities
							including critical SSRF and injection flaws.
						</p>
					</div>
				</FadeIn>

				<FadeIn delay={100}>
					<div className="grid grid-cols-2 md:grid-cols-4 gap-3 md:gap-4 mb-8 md:mb-10">
						{[
							{
								stat: "45%",
								label: "of AI-generated code contains vulnerabilities",
								source: "Kaspersky",
							},
							{
								stat: "2.74x",
								label: "more XSS vulnerabilities in AI co-written code",
								source: "CodeRabbit",
							},
							{
								stat: "10.3%",
								label: "of Lovable apps have critical RLS flaws",
								source: "Security Audit",
							},
							{
								stat: "69",
								label: "vulnerabilities found in 15 AI-built apps",
								source: "Tenzai Research",
							},
						].map((item, i) => (
							<div
								key={i}
								className="bg-kanagawa-surface rounded-xl border border-kanagawa-border p-3 md:p-5 text-center card-hover"
							>
								<div className="text-2xl md:text-3xl font-bold text-kanagawa-red mb-1">
									{item.stat}
								</div>
								<div className="text-xs text-kanagawa-fgMuted mb-1 md:mb-2">
									{item.label}
								</div>
								<div className="text-xs text-kanagawa-fgDim">{item.source}</div>
							</div>
						))}
					</div>
				</FadeIn>

				<FadeIn delay={200}>
					<div className="bg-kanagawa-surface rounded-2xl p-4 md:p-8 border border-kanagawa-border">
						<div className="text-center mb-6 md:mb-8">
							<h3 className="text-lg md:text-xl font-semibold text-kanagawa-fg mb-2">
								Why Vibe-Coded Apps Are at Risk
							</h3>
							<p className="text-xs md:text-sm text-kanagawa-fgDim">
								AI models optimize for working code, not secure code.
							</p>
						</div>
						<div className="grid grid-cols-1 md:grid-cols-3 gap-4 md:gap-6 text-left">
							<div>
								<div className="text-kanagawa-accent font-semibold text-xs md:text-sm mb-2">
									🚀 Speed Creates Blind Spots
								</div>
								<p className="text-kanagawa-fgMuted text-xs">
									AI coding tools build full-stack apps in minutes. They skip
									authentication checks, expose database credentials,
									misconfigure Supabase RLS policies, and leave API routes wide
									open.
								</p>
							</div>
							<div>
								<div className="text-kanagawa-accent font-semibold text-xs md:text-sm mb-2">
									🔓 The Attack Surface Is Growing
								</div>
								<p className="text-kanagawa-fgMuted text-xs">
									With Google AI Studio offering full-stack vibe coding with
									Firebase integration, and Lovable creating 200,000 new
									projects daily, attackers know where to look.
								</p>
							</div>
							<div>
								<div className="text-kanagawa-accent font-semibold text-xs md:text-sm mb-2">
									✅ VibeCheck Catches These Issues
								</div>
								<p className="text-kanagawa-fgMuted text-xs">
									Free, no signup required, gives you a security grade in
									seconds. Catches issues before your users do.
								</p>
							</div>
						</div>
					</div>
				</FadeIn>
			</div>
		</section>
	);
}

function Scanner({
	onScanComplete,
}: {
	onScanComplete?: () => Promise<void> | void;
}) {
	const [scanType, setScanType] = useState<ScanType>("github");
	const [url, setUrl] = useState("");
	const [isScanning, setIsScanning] = useState(false);
	const [result, setResult] = useState<ScanResult | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [scanProgress, setScanProgress] = useState(0);
	const [showResult, setShowResult] = useState(false);
	const [copiedId, setCopiedId] = useState<string | null>(null);
	const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

	const generateFixPrompt = (finding: Finding) => {
		const language =
			scanType === "github" ? "TypeScript/JavaScript" : "HTML/Server Config";
		const context = finding.filePath
			? `File: ${finding.filePath}${finding.lineNumber ? ` (line ${finding.lineNumber})` : ""}`
			: scanType === "github"
				? "Repository: " + url
				: "Website: " + url;

		return `You are a security expert. Fix this vulnerability in my ${language} project.

Context: ${context}

Severity: ${finding.severity.toUpperCase()}
Rule ID: ${finding.ruleId}

Vulnerability: ${finding.title}
Description: ${finding.description}
${finding.snippet ? `Code snippet:\n${finding.snippet.slice(0, 300)}` : ""}

Remediation: ${finding.remediation}

Please provide:
1. Root cause explanation
2. The exact code change needed (show before/after)
3. Any additional security notes

Do not explain what you would do — provide actual working code.`;
	};

	const handleCopyPrompt = (finding: Finding) => {
		const prompt = generateFixPrompt(finding);
		navigator.clipboard
			.writeText(prompt)
			.then(() => {
				setCopiedId(finding.id);
				setTimeout(() => setCopiedId(null), 2500);
			})
			.catch(() => {
				// Fallback for older browsers
				const textarea = document.createElement("textarea");
				textarea.value = prompt;
				document.body.appendChild(textarea);
				textarea.select();
				document.execCommand("copy");
				document.body.removeChild(textarea);
				setCopiedId(finding.id);
				setTimeout(() => setCopiedId(null), 2500);
			});
	};

	const handleScan = async () => {
		if (!url.trim()) return;
		setIsScanning(true);
		setError(null);
		setResult(null);
		setShowResult(false);
		setScanProgress(0);
		const scanStartTime = Date.now();
		const SCAN_DURATION_MS = 5000;

		// Animate progress bar over exactly 5 seconds
		const progressInterval = setInterval(() => {
			const elapsed = Date.now() - scanStartTime;
			const progress = Math.min((elapsed / SCAN_DURATION_MS) * 100, 95);
			setScanProgress(progress);
		}, 100);

		try {
			const res = await fetch("/api/scan", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ url: url.trim(), type: scanType }),
			});

			// Wait until exactly 5 seconds have passed
			const elapsed = Date.now() - scanStartTime;
			const remaining = SCAN_DURATION_MS - elapsed;
			if (remaining > 0) {
				await new Promise((r) => setTimeout(r, remaining));
			}

			clearInterval(progressInterval);
			setScanProgress(100);

			if (!res.ok) {
				const data = await res.json();
				const errorMsg = data.error || "Scan failed";
				// Provide friendly messages for specific errors
				if (res.status === 403 && scanType === "github") {
					throw new Error(
						"🔒 This repository is private. Only public GitHub repos can be scanned.",
					);
				}
				if (res.status === 404) {
					throw new Error(
						"🔍 Repository not found. Please check the URL and make sure the repo is public.",
					);
				}
				if (res.status === 429) {
					throw new Error(
						"⏳ Too many requests. Please wait a moment and try again.",
					);
				}
				throw new Error(errorMsg);
			}

			const data = await res.json();
			setResult(data);
			setTimeout(() => setShowResult(true), 300);
			// The /api/scan/{type} route is the canonical writer; it persists
			// the scan + each finding into Supabase. We just need to refresh
			// the displayed counters so the user sees the new unique apps /
			// unique vulnerabilities. We don't block the UI on the refetch.
			if (onScanComplete) {
				Promise.resolve(onScanComplete()).catch(() => {
					// Non-critical: stats will refresh on the next interaction.
				});
			}
		} catch (err) {
			clearInterval(progressInterval);
			setScanProgress(0);
			const msg = err instanceof Error ? err.message : "An error occurred";
			// Ensure private repo friendly message
			if (
				msg.toLowerCase().includes("private") ||
				msg.toLowerCase().includes("403")
			) {
				setError(
					"🔒 This repository is private. VibeChecker can only scan public repositories.",
				);
			} else {
				setError(msg);
			}
		} finally {
			setIsScanning(false);
		}
	};

	const totalFindings = result
		? Object.values(result.severityCounts).reduce((a, b) => a + b, 0)
		: 0;

	return (
		<section id="scanner" className="py-12 md:py-20 bg-kanagawa-surface">
			<div className="max-w-3xl mx-auto px-4 md:px-6">
				<FadeIn>
					<div className="text-center mb-8 md:mb-10">
						<h2 className="text-2xl md:text-3xl font-semibold tracking-tight text-kanagawa-fg mb-3">
							Scan Your App
						</h2>
						<p className="text-kanagawa-fgMuted text-sm md:text-base">
							Enter a GitHub repo or website URL to start scanning
						</p>
					</div>
				</FadeIn>
				<FadeIn delay={100}>
					<div className="bg-kanagawa-bg rounded-2xl shadow-xl border border-kanagawa-border p-4 md:p-8">
						<div className="flex gap-2 mb-6 md:mb-8">
							<button
								onClick={() => {
									setScanType("github");
									setResult(null);
									setError(null);
								}}
								className={`flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all ${scanType === "github" ? "bg-kanagawa-accent text-kanagawa-bg shadow-lg" : "bg-kanagawa-surface text-kanagawa-fgMuted hover:bg-kanagawa-surface2"}`}
							>
								<Github className="w-4 h-4" />
								GitHub
							</button>
							<button
								onClick={() => {
									setScanType("website");
									setResult(null);
									setError(null);
								}}
								className={`flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all ${scanType === "website" ? "bg-kanagawa-accent text-kanagawa-bg shadow-lg" : "bg-kanagawa-surface text-kanagawa-fgMuted hover:bg-kanagawa-surface2"}`}
							>
								<Globe className="w-4 h-4" />
								Website
							</button>
						</div>
						<div className="flex flex-col sm:flex-row gap-3 mb-6">
							<div className="flex-1 relative">
								<Terminal className="absolute left-3 md:left-4 top-1/2 -translate-y-1/2 w-4 md:w-5 h-4 md:h-5 text-kanagawa-fgDim" />
								<input
									type="text"
									value={url}
									onChange={(e) => setUrl(e.target.value)}
									placeholder={
										scanType === "github" ? "owner/repo" : "https://example.com"
									}
									className="w-full bg-kanagawa-surface border border-kanagawa-border rounded-xl pl-10 md:pl-12 pr-3 md:pr-4 py-3 md:py-4 text-sm text-kanagawa-fg placeholder:text-kanagawa-fgDim focus:outline-none focus:ring-2 focus:ring-kanagawa-accent focus:border-transparent transition"
									onKeyDown={(e) => e.key === "Enter" && handleScan()}
								/>
							</div>
							<button
								onClick={handleScan}
								disabled={isScanning || !url.trim()}
								className={`btn-scan px-6 md:px-8 py-3 md:py-4 rounded-xl text-kanagawa-bg font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 ${isScanning ? "scan-pulse" : ""}`}
							>
								{isScanning ? (
									<>
										<div className="spinner-kanagawa w-4 h-4" />
										<span className="scanning-dots">Scanning</span>
									</>
								) : (
									<>
										<ArrowRight className="w-4 h-4" />
										Scan
									</>
								)}
							</button>
						</div>
						{error && (
							<div className="p-4 rounded-xl bg-kanagawa-red/10 border border-kanagawa-red/30 text-kanagawa-red flex items-center gap-3 mb-6 animate-in slide-in-from-top-2">
								<AlertTriangle className="w-5 h-5 flex-shrink-0" />
								<span className="text-sm">{error}</span>
							</div>
						)}
						{isScanning && (
							<div className="space-y-4">
								<div className="flex items-center justify-between text-sm text-kanagawa-fgMuted">
									<span className="flex items-center gap-2">
										<div className="spinner-kanagawa w-4 h-4" />
										Scanning in progress...
									</span>
									<span>{Math.round(scanProgress)}%</span>
								</div>
								<div className="h-2 bg-kanagawa-surface rounded-full overflow-hidden">
									<div
										className="h-full progress-gradient rounded-full transition-all duration-500 ease-out"
										style={{ width: `${scanProgress}%` }}
									/>
								</div>
								<div className="space-y-2 text-sm text-kanagawa-fgMuted">
									<p className="flex items-center gap-2">
										<span className="w-1.5 h-1.5 rounded-full bg-kanagawa-accent pulse-dot" />
										Fetching {scanType === "github" ? "repository" : "website"}
										...
									</p>
									<p className="flex items-center gap-2">
										<span
											className="w-1.5 h-1.5 rounded-full bg-kanagawa-accent pulse-dot"
											style={{ animationDelay: "0.2s" }}
										/>
										Analyzing security headers...
									</p>
									<p className="flex items-center gap-2">
										<span
											className="w-1.5 h-1.5 rounded-full bg-kanagawa-accent pulse-dot"
											style={{ animationDelay: "0.4s" }}
										/>
										Running OWASP Top 10 checks...
									</p>
								</div>
							</div>
						)}
						{result && result.status === "completed" && showResult && (
							<div className="mt-8 pt-8 border-t border-kanagawa-border animate-in fade-in slide-in-from-top-4 duration-500">
								<div className="flex flex-col sm:flex-row sm:flex-wrap items-start sm:items-center gap-3 sm:gap-4 p-4 sm:p-5 rounded-xl bg-kanagawa-surface mb-6">
									<div className="flex items-center gap-2">
										<div className="w-10 h-10 rounded-full bg-kanagawa-accent/20 flex items-center justify-center">
											<CheckCircle className="w-5 h-5 text-kanagawa-accent" />
										</div>
										<div>
											<span className="text-sm font-medium text-kanagawa-fg">
												Scan complete
											</span>
											<span className="text-xs text-kanagawa-fgMuted ml-2">
												{result.scanDuration
													? `${(result.scanDuration / 1000).toFixed(1)}s`
													: ""}
											</span>
										</div>
									</div>
									<div className="text-sm text-kanagawa-fgMuted font-mono truncate max-w-full">
										{result.targetUrl}
									</div>
									<div className="flex flex-wrap gap-2 ml-auto items-center">
										{Object.entries(result.severityCounts).map(
											([sev, count]) =>
												count > 0 && (
													<span
														key={sev}
														className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium ${SEVERITY_STYLES[sev as Severity].bg} ${SEVERITY_STYLES[sev as Severity].text}`}
													>
														<span
															className={`w-1.5 h-1.5 rounded-full ${SEVERITY_STYLES[sev as Severity].dot}`}
														/>
														{count} {sev}
													</span>
												),
										)}
										<button
											onClick={() => downloadPDF(result)}
											className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-kanagawa-accent text-kanagawa-bg text-xs font-medium hover:bg-kanagawa-accentSoft transition-all hover:scale-[1.02] active:scale-[0.98] mt-1 sm:mt-0"
										>
											<FileText className="w-3.5 h-3.5" />
											PDF
										</button>
									</div>
								</div>
								{totalFindings === 0 ? (
									<div className="text-center py-12">
										<div className="w-16 h-16 rounded-full bg-kanagawa-green/20 flex items-center justify-center mx-auto mb-4 floating">
											<CheckCircle className="w-8 h-8 text-kanagawa-green" />
										</div>
										<h3 className="text-xl font-semibold text-kanagawa-fg mb-2">
											All Good!
										</h3>
										<p className="text-kanagawa-fgMuted">
											No security issues found. Your{" "}
											{scanType === "github" ? "repository" : "website"} passed
											all checks.
										</p>
									</div>
								) : (
									<div className="space-y-3">
										<div className="flex items-center justify-between">
											<h3 className="text-sm font-medium text-kanagawa-fg">
												{totalFindings} Issues Found
											</h3>
											<span className="text-xs text-kanagawa-fgMuted">
												Sorted by severity
											</span>
										</div>
										{result.findings
											.sort((a, b) => {
												const order = {
													critical: 0,
													high: 1,
													medium: 2,
													low: 3,
													info: 4,
												};
												return order[a.severity] - order[b.severity];
											})
											.map((finding) => (
												<div
													key={finding.id}
													role="button"
													tabIndex={0}
													onClick={() => setSelectedFinding(finding)}
													onKeyDown={(e) => {
														if (e.key === "Enter" || e.key === " ") {
															e.preventDefault();
															setSelectedFinding(finding);
														}
													}}
													className={`p-4 sm:p-5 rounded-xl border card-hover cursor-pointer focus:outline-none focus:ring-2 focus:ring-kanagawa-accent ${SEVERITY_STYLES[finding.severity].border} ${SEVERITY_STYLES[finding.severity].bg}`}
												>
													<div className="flex items-start gap-3">
														<SeverityBadge severity={finding.severity} />
														<div className="flex-1 min-w-0">
															<div className="flex flex-wrap items-center gap-2 mb-1">
																<span className="text-xs font-mono text-kanagawa-fgDim">
																	{finding.ruleId}
																</span>
																<h4 className="font-medium text-kanagawa-fg truncate flex-1">
																	{finding.title}
																</h4>
																{finding.score !== undefined && (
																	<span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-mono bg-kanagawa-bg border border-kanagawa-border text-kanagawa-fgMuted">
																		{scoreBadge(finding.score)}
																	</span>
																)}
																<ChevronRight className="w-4 h-4 text-kanagawa-fgDim shrink-0" />
															</div>
															<p className="text-sm text-kanagawa-fgMuted mb-3">
																{finding.description}
															</p>
															<div className="p-3 rounded-lg bg-kanagawa-bg border border-kanagawa-border mb-3">
																<p className="text-xs text-kanagawa-fgDim mb-1 font-medium">
																	How to Fix
																</p>
																<p className="text-sm text-kanagawa-fg">
																	{finding.remediation}
																</p>
															</div>
															<button
																onClick={() => handleCopyPrompt(finding)}
																className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
																	copiedId === finding.id
																		? "bg-kanagawa-green/20 text-kanagawa-green border border-kanagawa-green/40"
																		: "bg-kanagawa-accent text-kanagawa-bg hover:bg-kanagawa-accentSoft hover:scale-[1.02] active:scale-[0.98]"
																}`}
															>
																{copiedId === finding.id ? (
																	<>
																		<Check className="w-3.5 h-3.5" />
																		Copied!
																	</>
																) : (
																	<>
																		<Copy className="w-3.5 h-3.5" />
																		Copy Fix Prompt for AI
																	</>
																)}
															</button>
														</div>
													</div>
												</div>
											))}
									</div>
								)}
							</div>
						)}
					</div>
				</FadeIn>
			</div>

			<FindingDetailPanel
				finding={selectedFinding}
				onClose={() => setSelectedFinding(null)}
				onCopy={handleCopyPrompt}
			/>
		</section>
	);
}

function FindingDetailPanel({
	finding,
	onClose,
	onCopy,
}: {
	finding: Finding | null;
	onClose: () => void;
	onCopy: (f: Finding) => void;
}) {
	if (!finding) return null;

	const tier = finding.score !== undefined ? scoreTier(finding.score) : null;

	return (
		<div
			role="dialog"
			aria-modal="true"
			className="fixed inset-0 z-50 flex justify-end"
			onClick={onClose}
		>
			<div className="absolute inset-0 bg-kanagawa-bg/70 backdrop-blur-sm" />
			<aside
				className="relative w-full max-w-md h-full bg-kanagawa-bgSurface border-l border-kanagawa-border overflow-y-auto shadow-2xl"
				onClick={(e) => e.stopPropagation()}
			>
				<header className="sticky top-0 z-10 bg-kanagawa-bgSurface border-b border-kanagawa-border px-5 py-4 flex items-center justify-between gap-3">
					<div className="flex items-center gap-2 min-w-0">
						<SeverityBadge severity={finding.severity} />
						<span className="text-xs font-mono text-kanagawa-fgDim truncate">
							{finding.ruleId}
						</span>
					</div>
					<button
						type="button"
						onClick={onClose}
						aria-label="Close detail panel"
						className="p-1.5 rounded-md text-kanagawa-fgMuted hover:bg-kanagawa-bg hover:text-kanagawa-fg transition-colors"
					>
						<X className="w-4 h-4" />
					</button>
				</header>

				<div className="p-5 space-y-5">
					{finding.score !== undefined && tier && (
						<section>
							<div className={`rounded-lg border ${tier.border} ${tier.bg} px-4 py-3`}>
								<div className="flex items-baseline justify-between mb-2">
									<span className={`text-xs font-medium uppercase tracking-wide ${tier.color}`}>
										Contextual Risk Score
									</span>
									<span className={`text-2xl font-semibold tabular-nums ${tier.color}`}>
										{finding.score}
										<span className="text-sm text-kanagawa-fgDim ml-0.5">/100</span>
									</span>
								</div>
								<div className="h-1.5 w-full rounded-full bg-kanagawa-bg overflow-hidden">
									<div
										className={`h-full ${tier.color.replace("text-", "bg-")} transition-all`}
										style={{ width: `${finding.score}%` }}
									/>
								</div>
								<p className="text-xs text-kanagawa-fgMuted mt-2">
									{finding.score === 100
										? "Capped at 100. Multiple critical context signals stacked."
										: `Tier: ${tier.label}. Recomputed on every scan.`}
								</p>
							</div>

							{finding.riskFactors && finding.riskFactors.length > 0 && (
								<div className="mt-4">
									<h3 className="text-xs font-semibold uppercase tracking-wide text-kanagawa-fgDim mb-2">
										Why this score?
									</h3>
									<ul className="space-y-1.5">
										{finding.riskFactors.map((factor, i) => (
											<li
												key={i}
												className="flex items-start gap-2 text-sm text-kanagawa-fg"
											>
												<span className="mt-1.5 w-1 h-1 rounded-full bg-kanagawa-accent shrink-0" />
												<span>{factor}</span>
											</li>
										))}
									</ul>
								</div>
							)}
						</section>
					)}

					<section>
						<h2 className="text-lg font-semibold text-kanagawa-fg mb-2 leading-snug">
							{finding.title}
						</h2>
						<p className="text-sm text-kanagawa-fgMuted leading-relaxed">
							{finding.description}
						</p>
					</section>

					{(finding.filePath || finding.snippet) && (
						<section>
							{finding.filePath && (
								<div className="mb-3">
									<h3 className="text-xs font-semibold uppercase tracking-wide text-kanagawa-fgDim mb-1">
										Location
									</h3>
									<p className="text-sm font-mono text-kanagawa-fg">
										{finding.filePath}
										{finding.lineNumber !== undefined && (
											<span className="text-kanagawa-fgDim">
												{" "}:{finding.lineNumber}
											</span>
										)}
									</p>
								</div>
							)}
							{finding.snippet && (
								<div>
									<h3 className="text-xs font-semibold uppercase tracking-wide text-kanagawa-fgDim mb-1">
										Code Snippet
									</h3>
									<pre className="p-3 rounded-lg bg-kanagawa-bg border border-kanagawa-border text-xs font-mono text-kanagawa-fg overflow-x-auto whitespace-pre">
										{finding.snippet}
									</pre>
								</div>
							)}
						</section>
					)}

					<section>
						<h3 className="text-xs font-semibold uppercase tracking-wide text-kanagawa-fgDim mb-2">
							How to Fix
						</h3>
						<div className="p-4 rounded-lg bg-kanagawa-bg border border-kanagawa-border">
							<p className="text-sm text-kanagawa-fg leading-relaxed">
								{finding.remediation}
							</p>
						</div>
					</section>

					<button
						type="button"
						onClick={() => onCopy(finding)}
						className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-kanagawa-accent text-kanagawa-bg text-sm font-medium hover:bg-kanagawa-accentSoft transition-colors"
					>
						<Copy className="w-4 h-4" />
						Copy Fix Prompt for AI
					</button>
				</div>
			</aside>
		</div>
	);
}

function HowItWorks() {
	return (
		<section id="how" className="py-12 md:py-20 bg-kanagawa-bg">
			<div className="max-w-5xl mx-auto px-4 md:px-6">
				<FadeIn>
					<div className="text-center mb-8 md:mb-14">
						<h2 className="text-2xl md:text-3xl font-semibold tracking-tight text-kanagawa-fg mb-3">
							Two Ways to Scan
						</h2>
						<p className="text-kanagawa-fgMuted max-w-xl mx-auto text-sm md:text-base">
							Most security scanners only do one or the other. VibeCheck does
							both.
						</p>
					</div>
				</FadeIn>
				<div className="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">
					<FadeIn delay={100}>
						<div className="bg-gradient-to-br from-kanagawa-surface to-kanagawa-surface2 rounded-2xl p-4 md:p-6 lg:p-8 border border-kanagawa-border text-kanagawa-fg h-full">
							<div className="flex items-center gap-3 mb-3 md:mb-4">
								<div className="w-10 h-10 md:w-12 md:h-12 rounded-xl bg-kanagawa-accent/20 flex items-center justify-center">
									<Github className="w-5 h-5 md:w-6 md:h-6 text-kanagawa-accent" />
								</div>
								<h3 className="text-lg md:text-xl font-semibold">
									Source Code Scanner
								</h3>
							</div>
							<p className="text-kanagawa-fgMuted text-xs md:text-sm mb-4 md:mb-6">
								Analyzes your GitHub repository for hardcoded secrets, exposed
								credentials, misconfigurations, and vulnerable patterns in your
								code.
							</p>
							<div className="space-y-1.5 md:space-y-2">
								{[
									"Exposed API keys and secrets (OpenAI, Stripe, Supabase)",
									"Firebase misconfigurations without proper security rules",
									"Supabase without Row Level Security (RLS)",
									"Database credentials hardcoded in source files",
									"JWT secrets exposed in codebase",
									"Environment files (.env) committed to repository",
									"Unprotected API routes handling sensitive operations",
									"Open CORS policies allowing any website to call your API",
									"SQL injection vulnerabilities from string concatenation",
									"Missing input validation on API endpoints",
									"Missing security headers (XSS, clickjacking)",
									"Vulnerable dependencies in package.json",
									"Missing rate limiting on public API routes",
								].map((item, i) => (
									<div
										key={i}
										className="flex items-start gap-2 text-xs md:text-sm text-kanagawa-fgMuted"
									>
										<CheckCircle className="w-3.5 h-3.5 md:w-4 md:h-4 text-kanagawa-green mt-0.5 flex-shrink-0" />
										<span>{item}</span>
									</div>
								))}
							</div>
						</div>
					</FadeIn>
					<FadeIn delay={200}>
						<div className="bg-gradient-to-br from-kanagawa-violet/30 to-kanagawa-surface rounded-2xl p-4 md:p-6 lg:p-8 border border-kanagawa-violet/30 text-kanagawa-fg h-full">
							<div className="flex items-center gap-3 mb-3 md:mb-4">
								<div className="w-10 h-10 md:w-12 md:h-12 rounded-xl bg-kanagawa-violet/20 flex items-center justify-center">
									<Globe className="w-5 h-5 md:w-6 md:h-6 text-kanagawa-accentSoft" />
								</div>
								<h3 className="text-lg md:text-xl font-semibold">
									Live Site Scanner
								</h3>
							</div>
							<p className="text-kanagawa-fgMuted text-xs md:text-sm mb-4 md:mb-6">
								Checks your deployed application for security headers, exposed
								files, CORS misconfigurations, and technology fingerprints.
							</p>
							<div className="space-y-1.5 md:space-y-2">
								{[
									"Content-Security-Policy (CSP) header",
									"HSTS (HTTP Strict Transport Security)",
									"X-Frame-Options (clickjacking protection)",
									"X-Content-Type-Options (MIME sniffing)",
									"Referrer-Policy and Permissions-Policy",
									"SSL/TLS configuration and HTTP to HTTPS redirect",
									"Exposed sensitive files (.env, .git/config, phpinfo)",
									"CORS misconfigurations for cross-origin attacks",
									"Cookie security flags (HttpOnly, Secure, SameSite)",
									"Technology fingerprinting in headers",
								].map((item, i) => (
									<div
										key={i}
										className="flex items-start gap-2 text-xs md:text-sm text-kanagawa-fgMuted"
									>
										<CheckCircle className="w-3.5 h-3.5 md:w-4 md:h-4 text-kanagawa-accent mt-0.5 flex-shrink-0" />
										<span>{item}</span>
									</div>
								))}
							</div>
						</div>
					</FadeIn>
				</div>
			</div>
		</section>
	);
}

function BestPractices() {
	const practices = [
		{
			icon: Lock,
			title: "1. Enable Row Level Security (RLS)",
			description:
				"Always enable Row Level Security on your Supabase tables. Without RLS, anyone with your anon key can read and modify your entire database.",
			code: "ALTER TABLE users ENABLE ROW LEVEL SECURITY;",
			tags: ["Supabase", "Database"],
		},
		{
			icon: Shield,
			title: "2. Use Environment Variables for Secrets",
			description:
				"Never hardcode API keys, database passwords, or JWT secrets in your source code. Use environment variables and secrets managers.",
			code: "const apiKey = process.env.SUPABASE_KEY;",
			tags: ["Secrets", "Environment"],
		},
		{
			icon: Globe,
			title: "3. Implement Security Headers",
			description:
				"Add security headers like CSP, HSTS, and X-Frame-Options to protect against XSS, clickjacking, and protocol downgrade attacks.",
			code: "Strict-Transport-Security: max-age=31536000",
			tags: ["Headers", "HTTPS"],
		},
		{
			icon: FileCode,
			title: "4. Sanitize User Input",
			description:
				"Always validate and sanitize user input. Use parameterized queries to prevent SQL injection and output encoding to prevent XSS.",
			code: "// Use parameterized queries\nconst { data } = await supabase\n  .from('users')\n  .select('*')\n  .eq('id', userId);",
			tags: ["Injection", "Validation"],
		},
		{
			icon: AlertTriangle,
			title: "5. Scan Dependencies for Vulnerabilities",
			description:
				"Regularly audit your dependencies for known vulnerabilities. Update packages and use lock files to prevent supply chain attacks.",
			code: "npm audit && npm update",
			tags: ["Dependencies", "Supply Chain"],
		},
		{
			icon: Users,
			title: "6. Implement Proper Authentication",
			description:
				"Always authenticate users before granting access. Use secure session management, enforce strong passwords, and implement MFA for sensitive operations.",
			code: "// Verify user session on protected routes\nconst { user } = await supabase.auth.getUser();\nif (!user) return NextResponse.redirect('/login');",
			tags: ["Auth", "Sessions"],
		},
	];

	return (
		<section id="best-practices" className="py-12 md:py-20 bg-kanagawa-surface">
			<div className="max-w-5xl mx-auto px-4 md:px-6">
				<FadeIn>
					<div className="text-center mb-8 md:mb-14">
						<h2 className="text-2xl md:text-3xl font-semibold tracking-tight text-kanagawa-fg mb-3">
							Web App Security Best Practices
						</h2>
						<p className="text-kanagawa-fgMuted max-w-xl mx-auto text-sm md:text-base">
							Implement these 6 practices to secure your vibe-coded applications
						</p>
					</div>
				</FadeIn>
				<div className="grid grid-cols-1 lg:grid-cols-2 gap-4 md:gap-6">
					{practices.map((practice, i) => (
						<FadeIn key={i} delay={i * 100}>
							<div className="bg-kanagawa-bg rounded-2xl p-5 md:p-6 border border-kanagawa-border hover:border-kanagawa-accent/40 hover:shadow-lg transition-all duration-300 group">
								<div className="flex items-start gap-4">
									<div className="w-10 h-10 md:w-12 md:h-12 rounded-xl bg-kanagawa-accent/15 group-hover:bg-kanagawa-accent/25 flex items-center justify-center flex-shrink-0 transition-colors">
										<practice.icon className="w-5 h-5 md:w-6 md:h-6 text-kanagawa-accent" />
									</div>
									<div className="flex-1 min-w-0">
										<h3 className="font-semibold text-kanagawa-fg mb-2 text-sm md:text-base">
											{practice.title}
										</h3>
										<p className="text-kanagawa-fgMuted text-xs md:text-sm mb-3">
											{practice.description}
										</p>
										<div className="bg-kanagawa-surface rounded-lg p-3 mb-3 overflow-x-auto border border-kanagawa-border">
											<code className="text-kanagawa-green text-xs font-mono whitespace-nowrap">
												{practice.code}
											</code>
										</div>
										<div className="flex flex-wrap gap-2">
											{practice.tags.map((tag, j) => (
												<span
													key={j}
													className="px-2 py-1 rounded-full bg-kanagawa-surface text-kanagawa-fgMuted text-xs"
												>
													{tag}
												</span>
											))}
										</div>
									</div>
								</div>
							</div>
						</FadeIn>
					))}
				</div>
				<FadeIn delay={500}>
					<div className="mt-8 text-center">
						<a
							href="#scanner"
							className="inline-flex items-center gap-2 text-kanagawa-accent hover:text-kanagawa-accentSoft font-medium text-sm transition-colors"
						>
							<Bug className="w-4 h-4" />
							Scan your app to find issues
							<ArrowRight className="w-4 h-4" />
						</a>
					</div>
				</FadeIn>
			</div>
		</section>
	);
}

function Features() {
	const features = [
		{
			icon: Shield,
			title: "OWASP Top 10 2025",
			description:
				"Coverage including NEW A03 Supply Chain and A10 Error Handling categories.",
		},
		{
			icon: Zap,
			title: "Lightning Fast",
			description: "Get detailed security findings in seconds, not hours.",
		},
		{
			icon: Lock,
			title: "No Signup Required",
			description:
				"Start scanning immediately. No account, no email, no credit card.",
		},
		{
			icon: FileCode,
			title: "AI Fix Prompts",
			description:
				"Copy a detailed fix prompt for each vulnerability and paste it into your AI agent.",
		},
		{
			icon: BarChart3,
			title: "Severity Ratings",
			description:
				"Issues categorized by criticality to prioritize your fixes.",
		},
		{
			icon: Globe,
			title: "GitHub & Websites",
			description: "Scan public GitHub repos or any website URL.",
		},
		{
			icon: AlertTriangle,
			title: "Slopsquatting Detection",
			description:
				"Detect AI-hallucinated packages that attackers can register as malicious.",
		},
		{
			icon: Bug,
			title: "Supabase RLS Scan",
			description:
				"Find Row Level Security misconfigurations — the #1 issue in vibe-coded apps.",
		},
	];
	return (
		<section id="features" className="py-12 md:py-20 bg-kanagawa-surface">
			<div className="max-w-5xl mx-auto px-4 md:px-6">
				<FadeIn>
					<div className="text-center mb-8 md:mb-14">
						<h2 className="text-2xl md:text-3xl font-semibold tracking-tight text-kanagawa-fg mb-3">
							Everything You Need
						</h2>
						<p className="text-kanagawa-fgMuted max-w-xl mx-auto text-sm md:text-base">
							Professional-grade security scanning, completely free
						</p>
					</div>
				</FadeIn>
				<div className="grid grid-cols-2 md:grid-cols-2 lg:grid-cols-4 gap-3 md:gap-4 lg:gap-6">
					{features.map((feature, i) => (
						<FadeIn key={i} delay={i * 100}>
							<div className="feature-card group p-4 md:p-5 lg:p-6 rounded-2xl bg-kanagawa-bg border border-kanagawa-border h-full">
								<div className="w-9 h-9 md:w-10 md:h-10 lg:w-12 lg:h-12 rounded-xl bg-kanagawa-accent/15 group-hover:bg-kanagawa-accent/25 flex items-center justify-center mb-3 md:mb-4 transition-colors">
									<feature.icon className="w-4 h-4 md:w-5 md:h-5 lg:w-6 lg:h-6 text-kanagawa-accent" />
								</div>
								<h3 className="font-semibold text-kanagawa-fg mb-1 md:mb-2 text-xs md:text-sm lg:text-base">
									{feature.title}
								</h3>
								<p className="text-xs text-kanagawa-fgMuted leading-relaxed">
									{feature.description}
								</p>
							</div>
						</FadeIn>
					))}
				</div>
			</div>
		</section>
	);
}

function Testimonials() {
	const testimonials = [
		{
			quote:
				"Found a critical XSS in my app before launch. Saved me from a potential disaster.",
			author: "Sarah Chen",
			role: "Indie Hacker",
		},
		{
			quote:
				"The actionable remediation steps are gold. Fixed all issues in under an hour.",
			author: "Marcus Rivera",
			role: "Solo Founder",
		},
		{
			quote:
				"Finally a free scanner that actually works. Built right into my workflow.",
			author: "Alex Thompson",
			role: "CTO",
		},
	];
	return (
		<section className="py-12 md:py-20 bg-kanagawa-bg">
			<div className="max-w-5xl mx-auto px-4 md:px-6">
				<FadeIn>
					<div className="text-center mb-8 md:mb-14">
						<h2 className="text-2xl md:text-3xl font-semibold tracking-tight text-kanagawa-fg mb-3">
							Loved by Developers
						</h2>
						<p className="text-kanagawa-fgMuted text-sm md:text-base">
							Join thousands of developers who ship safer code
						</p>
					</div>
				</FadeIn>
				<div className="grid grid-cols-1 md:grid-cols-3 gap-4 md:gap-6">
					{testimonials.map((t, i) => (
						<FadeIn key={i} delay={i * 100}>
							<div className="card-hover p-4 md:p-6 rounded-2xl bg-kanagawa-surface border border-kanagawa-border">
								<div className="flex gap-1 mb-3 md:mb-4">
									{[...Array(5)].map((_, j) => (
										<Star
											key={j}
											className="w-4 h-4 fill-kanagawa-yellow text-kanagawa-yellow"
										/>
									))}
								</div>
								<p className="text-kanagawa-fgMuted text-sm mb-3 md:mb-4">
									"{t.quote}"
								</p>
								<div>
									<div className="font-medium text-kanagawa-fg text-sm">
										{t.author}
									</div>
									<div className="text-xs text-kanagawa-fgDim">{t.role}</div>
								</div>
							</div>
						</FadeIn>
					))}
				</div>
			</div>
		</section>
	);
}

function CTA() {
	return (
		<section className="py-16 md:py-20 bg-gradient-to-br from-kanagawa-surface to-kanagawa-surface2 relative overflow-hidden">
			<div className="absolute inset-0 overflow-hidden pointer-events-none">
				<FloatingParticles />
			</div>
			<div className="relative max-w-3xl mx-auto px-6 text-center">
				<FadeIn>
					<h2 className="text-3xl md:text-4xl font-semibold tracking-tight text-kanagawa-fg mb-4">
						Need Help Fixing the Issues?
					</h2>
					<p className="text-lg text-kanagawa-fgMuted mb-4">
						Every finding includes an "AI Fix Prompt" — copy it and paste into
						your favorite AI agent for step-by-step fix instructions.
					</p>
					<p className="text-md text-kanagawa-accent mb-8">
						Free • No Signup • Works with Lovable, Bolt, Cursor, Replit & more
					</p>
					<a
						href="#scanner"
						className="btn-glow group inline-flex items-center gap-2 px-8 py-4 rounded-xl bg-kanagawa-accent text-kanagawa-bg font-medium hover:bg-kanagawa-accentSoft transition-all hover:gap-3 border-glow"
					>
						Scan Your App Now{" "}
						<ArrowRight className="w-5 h-5 transition-transform group-hover:translate-x-1" />
					</a>
				</FadeIn>
			</div>
		</section>
	);
}

function Footer() {
	return (
		<footer className="border-t border-kanagawa-border bg-kanagawa-bg py-8">
			<div className="max-w-5xl mx-auto px-6">
				<div className="flex flex-col items-center gap-4 text-center">
					<a
						href="#scanner"
						className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-kanagawa-accent text-kanagawa-bg text-sm font-medium hover:bg-kanagawa-accentSoft transition"
					>
						Free Security Scanner for Vibe-Coded Apps
					</a>
					<div className="text-sm text-kanagawa-fgDim">
						<p className="font-medium mb-1">Donations (SOL Mainnet)</p>
						<code className="font-mono text-xs break-all">8ZNN5bomP4SVfDthfcFgXBSoZAgtngZAcKscddhoPrGA</code>
					</div>
					<p className="text-sm text-kanagawa-fgDim">
						Copyright © {new Date().getFullYear()}
					</p>
				</div>
			</div>
		</footer>
	);
}

export default function Home() {
	const [statsData, setStatsData] = useState<StatsData>({
		uniqueSites: 0,
		totalScans: 0,
		uniqueVulnerabilities: 0,
		totalVulnerabilities: 0,
	});
	const [statsLoaded, setStatsLoaded] = useState(false);

	// Pull the real, deduplicated counters from the server. The four values
	// come straight from Supabase aggregates (see /api/stats) - in particular
	// `uniqueVulnerabilities` is the count of distinct rule_ids across every
	// scan we have ever performed, so re-scanning the same site never doubles
	// a counter.
	const refetchStats = useCallback(async () => {
		try {
			const res = await fetch("/api/stats", { method: "GET" });
			if (!res.ok) return;
			const data = await res.json();
			setStatsData({
				uniqueSites: data.uniqueSites || 0,
				totalScans: data.totalScans || 0,
				uniqueVulnerabilities: data.uniqueVulnerabilities || 0,
				totalVulnerabilities: data.totalVulnerabilities || 0,
			});
		} catch {
			// Stats are non-critical; ignore transient failures.
		} finally {
			setStatsLoaded(true);
		}
	}, []);

	// Initial load
	useEffect(() => {
		refetchStats();
	}, [refetchStats]);

	return (
		<main className="min-h-screen bg-kanagawa-bg text-kanagawa-fg antialiased">
			<Header />
			<Hero />
			<Stats statsData={statsData} loaded={statsLoaded} />
			<RealityCheck />
			<Scanner onScanComplete={refetchStats} />
			<HowItWorks />
			<BestPractices />
			<Features />
			<Testimonials />
			<CTA />
			<Footer />
		</main>
	);
}