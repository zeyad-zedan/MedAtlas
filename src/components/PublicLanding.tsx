import React, { useState, useEffect } from 'react';
import {
  BookOpen,
  CheckCircle2,
  Clock,
  FileSpreadsheet,
  Lock,
  ShieldCheck,
  SlidersHorizontal,
  TrendingUp,
  ArrowRight,
  X,
} from 'lucide-react';
import { api, type UserProfile } from '../lib/api.ts';

interface PublicLandingProps {
  catalog: {
    subjects: any[];
    lectures: any[];
    totalPublishedQuestions: number;
  } | null;
  loadingCatalog: boolean;
  onAuthenticated: (user: UserProfile, initialTab?: string) => void;
}

type AuthTab = 'login' | 'register' | 'reset';
type LegalModalType = 'about' | 'contact' | 'privacy' | 'terms' | null;

export const PublicLanding: React.FC<PublicLandingProps> = ({
  catalog,
  loadingCatalog,
  onAuthenticated,
}) => {
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authTab, setAuthTab] = useState<AuthTab>('login');
  const [legalModal, setLegalModal] = useState<LegalModalType>(null);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [recoveryToken, setRecoveryToken] = useState('');
  const [resetStep, setResetStep] = useState<'request' | 'confirm'>('request');
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);

  // Automatically detect Firebase Auth password-reset oobCode, recovery token, or return from hosted action page
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const mode = params.get('mode')?.trim() || '';
    let urlCode =
      params.get('oobCode')?.trim() ||
      params.get('resetToken')?.trim() ||
      params.get('token')?.trim() ||
      '';

    if (!urlCode) {
      const continueUrlParam = params.get('continueUrl')?.trim();
      if (continueUrlParam) {
        try {
          const innerParams = new URL(continueUrlParam).searchParams;
          urlCode =
            innerParams.get('oobCode')?.trim() ||
            innerParams.get('resetToken')?.trim() ||
            innerParams.get('token')?.trim() ||
            '';
        } catch {
          // Ignore malformed continueUrl
        }
      }
    }

    if (urlCode.length >= 10) {
      setRecoveryToken(urlCode);
      setAuthTab('reset');
      setResetStep('confirm');
      setAuthError(null);
      setAuthSuccess(
        'Recovery code detected from your password reset link. Enter your new password below.'
      );
      setAuthModalOpen(true);
      // Strip sensitive recovery code from browser address bar & Referer history
      const cleanUrl = window.location.pathname + window.location.hash;
      window.history.replaceState({}, document.title, cleanUrl);
    } else if (mode === 'resetPassword') {
      setAuthTab('login');
      setResetStep('request');
      setAuthError(null);
      setAuthSuccess(
        'If you already updated your password on the verification page, sign in below with your new password to synchronize your MedAtlas account. Otherwise, select the Reset Password tab to paste your reset link.'
      );
      setAuthModalOpen(true);
      const cleanUrl = window.location.pathname + window.location.hash;
      window.history.replaceState({}, document.title, cleanUrl);
    }
  }, []);

  const openAuth = (tab: AuthTab) => {
    setAuthTab(tab);
    setResetStep('request');
    setRecoveryToken('');
    setAuthError(null);
    setAuthSuccess(null);
    setAuthModalOpen(true);
  };

  const handleEmailAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);
    setAuthLoading(true);
    try {
      if (authTab === 'register') {
        const user = await api.registerWithEmail(email, password, displayName);
        setAuthModalOpen(false);
        onAuthenticated(user, 'dashboard');
      } else if (authTab === 'login') {
        const user = await api.loginWithEmail(email, password);
        setAuthModalOpen(false);
        onAuthenticated(user, 'dashboard');
      } else if (authTab === 'reset') {
        if (resetStep === 'request') {
          const res = await api.requestPasswordReset(email);
          setAuthSuccess(res.message);
          setResetStep('confirm');
        } else {
          const res = await api.confirmPasswordReset(recoveryToken.trim(), password);
          setAuthSuccess(res.message);
          setRecoveryToken('');
          setPassword('');
          setResetStep('request');
          setAuthTab('login');
        }
      }
    } catch (err: any) {
      setAuthError(err.message || 'Authentication failed.');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    setAuthError(null);
    setAuthLoading(true);
    try {
      const user = await api.loginWithGooglePopup();
      setAuthModalOpen(false);
      onAuthenticated(user, 'dashboard');
    } catch (err: any) {
      setAuthError(
        err.message ||
          'Google sign-in popup could not complete. You can also sign in with Email & Password below.'
      );
    } finally {
      setAuthLoading(false);
    }
  };

  const subjects = catalog?.subjects || [];
  const lectures = catalog?.lectures || [];
  const totalQuestions = catalog?.totalPublishedQuestions || 0;

  return (
    <div className="min-h-screen flex flex-col bg-[#F8FAFC] text-[#0F172A]">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="sticky top-0 z-30 flex items-center justify-between gap-8 px-6 lg:px-12 py-4 bg-white/95 backdrop-blur border-b border-slate-200">
        {/* Zone 1: Brand Title Wordmark (single element) */}
        <a
          href="#top"
          className="text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0"
        >
          MedAtlas MCQ
        </a>

        {/* Zone 2: 4 Concise Single-Line Navigation Links */}
        <nav
          aria-label="Primary Navigation"
          className="hidden md:flex items-center gap-7 text-sm font-medium text-slate-600"
        >
          <a
            href="#subjects"
            className="hover:text-slate-900 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Subjects
          </a>
          <a
            href="#lectures"
            className="hover:text-slate-900 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Lectures
          </a>
          <a
            href="#practice-modes"
            className="hover:text-slate-900 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Exam Modes
          </a>
          <a
            href="#analytics"
            className="hover:text-slate-900 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Progress Tracking
          </a>
        </nav>

        {/* Zone 3: 1 Primary Action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={() => openAuth('login')}
            className="px-4 py-2 text-sm font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Sign In / Register
          </button>
        </div>
      </header>

      <main id="top" className="flex-1">
        {/* Hero Section */}
        <section className="max-w-7xl mx-auto px-6 lg:px-12 pt-14 pb-16 border-b border-slate-200">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-stretch">
            <div className="lg:col-span-7 flex flex-col justify-between space-y-6">
              <div className="space-y-4">
                <p className="text-xs font-medium text-[#0284C7] tracking-wide">
                  Open Academic Trial Release · Full Curriculum Access · Zero Paywalls
                </p>
                <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight text-slate-900 leading-[1.15]">
                  Lecture-aligned medical multiple-choice mastery built for clinical reasoning.
                </h1>
                <p className="text-base sm:text-lg text-slate-600 leading-relaxed max-w-2xl">
                  Organize foundational and organ-system study by subject and lecture. Practice with immediate option-by-option explanations in Study Mode, simulate timed assessments in Exam Mode, and track longitudinal accuracy across every medical topic.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => openAuth('register')}
                  className="inline-flex items-center gap-2 px-5 py-3 text-sm font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Create Student Account
                  <ArrowRight className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={() => openAuth('login')}
                  disabled={authLoading}
                  className="px-4 py-3 text-sm font-semibold text-slate-800 bg-white border border-slate-300 hover:bg-slate-50 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Sign In to Account
                </button>
                <a
                  href="#subjects"
                  className="px-4 py-3 text-sm font-medium text-slate-600 hover:text-slate-900 bg-slate-100 hover:bg-slate-200/70 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Browse Curriculum
                </a>
              </div>

              {/* Real Database Catalog Metrics */}
              <div className="grid grid-cols-3 gap-6 pt-6 border-t border-slate-200">
                <div>
                  <p className="text-2xl font-bold font-mono-tabular text-slate-900">
                    {loadingCatalog ? '—' : subjects.length}
                  </p>
                  <p className="text-xs text-slate-500 mt-0.5">Published Subjects</p>
                </div>
                <div>
                  <p className="text-2xl font-bold font-mono-tabular text-slate-900">
                    {loadingCatalog ? '—' : lectures.length}
                  </p>
                  <p className="text-xs text-slate-500 mt-0.5">Structured Lectures</p>
                </div>
                <div>
                  <p className="text-2xl font-bold font-mono-tabular text-slate-900">
                    {loadingCatalog ? '—' : totalQuestions}
                  </p>
                  <p className="text-xs text-slate-500 mt-0.5">Peer-Reviewed MCQs</p>
                </div>
              </div>
            </div>

            {/* Interactive Academic Specimen Preview Card */}
            <div className="lg:col-span-5 flex flex-col justify-between bg-white rounded-xl border border-slate-200 p-6 space-y-5">
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs text-slate-500">
                  <span>Histology &amp; Cell Biology · Lecture 1</span>
                  <span className="font-mono-tabular">Difficulty: Medium</span>
                </div>
                <p className="text-sm font-serif-academic text-slate-900 leading-relaxed">
                  A 9-month-old infant presents with coarse facial features, gingival hyperplasia, and corneal clouding. Cultured fibroblasts show decreased intracellular acid hydrolase activity with elevated serum hydrolases. Defective phosphorylation of which carbohydrate residue in the cis-Golgi explains this finding?
                </p>
              </div>

              <div className="space-y-2 text-xs">
                <div className="p-2.5 rounded-lg border border-slate-200 text-slate-600">
                  <span className="font-mono-tabular font-semibold mr-2">A.</span>
                  Galactose on sphingolipids
                </div>
                <div className="p-2.5 rounded-lg border border-emerald-600/40 bg-emerald-50/60 text-emerald-950 font-medium">
                  <div className="flex items-center justify-between">
                    <span>
                      <span className="font-mono-tabular font-semibold mr-2">B.</span>
                      Mannose on N-linked oligosaccharides
                    </span>
                    <span className="text-xs font-semibold text-emerald-700 whitespace-nowrap">
                      ✓ Correct Answer
                    </span>
                  </div>
                </div>
                <div className="p-2.5 rounded-lg border border-slate-200 text-slate-600">
                  <span className="font-mono-tabular font-semibold mr-2">C.</span>
                  Serine-linked N-acetylgalactosamine
                </div>
                <div className="p-2.5 rounded-lg border border-slate-200 text-slate-600">
                  <span className="font-mono-tabular font-semibold mr-2">D.</span>
                  Sialic acid on gangliosides
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-700 space-y-1.5">
                <p className="font-semibold text-slate-900">
                  Explanation (Study Mode Rationale):
                </p>
                <p className="leading-relaxed">
                  Inclusion-cell (I-cell) disease results from defective N-acetylglucosamine-1-phosphotransferase in the cis-Golgi, preventing formation of mannose-6-phosphate (M6P) needed to route lysosomal enzymes via clathrin-coated vesicles.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Overview of Available Medical Subjects */}
        <section id="subjects" className="max-w-7xl mx-auto px-6 lg:px-12 py-14 border-b border-slate-200">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 mb-8">
            <div>
              <h2 className="text-2xl font-bold text-slate-900">
                Available Medical Subjects
              </h2>
              <p className="text-sm text-slate-600 mt-1">
                Hierarchical curriculum organized into Subjects → Lectures → Question Banks.
              </p>
            </div>
            <button
              type="button"
              onClick={() => openAuth('login')}
              className="text-sm font-semibold text-[#0284C7] hover:text-[#0369A1] inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
            >
              Sign in to begin solving questions
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          {loadingCatalog ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {[1, 2, 3, 4].map((n) => (
                <div
                  key={n}
                  className="h-40 rounded-xl border border-slate-200 bg-white p-6 animate-pulse"
                />
              ))}
            </div>
          ) : subjects.length === 0 ? (
            <div className="rounded-xl border border-slate-200 bg-white p-8 text-center">
              <p className="text-sm font-medium text-slate-700">
                No subjects have been published yet.
              </p>
              <p className="text-xs text-slate-500 mt-1">
                Administrators can publish subjects and import question banks from the Admin Console.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {subjects.map((subject, idx) => (
                <div
                  key={subject.id}
                  className="rounded-xl border border-slate-200 bg-white p-6 flex flex-col justify-between hover:border-slate-300 transition-colors"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs text-slate-500 font-mono-tabular">
                      <span>0{idx + 1}. Subject Module</span>
                      <span>
                        {subject.lectureCount} Lectures · {subject.questionCount} MCQs
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-slate-900">{subject.title}</h3>
                    <p className="text-sm text-slate-600 leading-relaxed">
                      {subject.description}
                    </p>
                  </div>

                  <div className="pt-5 mt-5 border-t border-slate-100 flex items-center justify-between text-xs text-slate-600">
                    <span>
                      Includes Study Mode, Timed Mock Exam &amp; Custom Filtering
                    </span>
                    <button
                      type="button"
                      onClick={() => openAuth('login')}
                      className="font-semibold text-[#0284C7] hover:text-[#0369A1] whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Open Subject →
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Featured & Recently Added Lectures */}
        <section id="lectures" className="max-w-7xl mx-auto px-6 lg:px-12 py-14 border-b border-slate-200">
          <div className="mb-8">
            <h2 className="text-2xl font-bold text-slate-900">
              Featured &amp; Recently Added Lectures
            </h2>
            <p className="text-sm text-slate-600 mt-1">
              Every lecture includes high-yield summary notes, formative practice questions, and timed mock assessments.
            </p>
          </div>

          {loadingCatalog ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {[1, 2, 3].map((n) => (
                <div
                  key={n}
                  className="h-36 rounded-xl border border-slate-200 bg-white p-5 animate-pulse"
                />
              ))}
            </div>
          ) : lectures.length === 0 ? (
            <div className="rounded-xl border border-slate-200 bg-white p-8 text-center text-sm text-slate-600">
              No published lectures available yet.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {lectures.slice(0, 6).map((lect) => (
                <div
                  key={lect.id}
                  className="rounded-xl border border-slate-200 bg-white p-5 flex flex-col justify-between"
                >
                  <div className="space-y-2">
                    <p className="text-xs text-slate-500">
                      {lect.subjectTitle} · Lecture {lect.lectureNumber}
                    </p>
                    <h3 className="text-base font-bold text-slate-900 leading-snug">
                      {lect.title}
                    </h3>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      {lect.description}
                    </p>
                  </div>
                  <div className="pt-4 mt-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 font-mono-tabular">
                    <span>
                      {lect.questionCount} MCQs · ~{lect.estimatedMinutes} min
                    </span>
                    <button
                      type="button"
                      onClick={() => openAuth('login')}
                      className="font-sans font-semibold text-[#0284C7] hover:text-[#0369A1] cursor-pointer"
                    >
                      Practice
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Practice & Examination Features */}
        <section id="practice-modes" className="max-w-7xl mx-auto px-6 lg:px-12 py-14 border-b border-slate-200">
          <div className="mb-8">
            <h2 className="text-2xl font-bold text-slate-900">
              Three Distinct Learning &amp; Assessment Modes
            </h2>
            <p className="text-sm text-slate-600 mt-1">
              Engineered for active recall, realistic board-style examination timing, and targeted remediation.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-3">
              <div className="w-9 h-9 rounded-lg bg-sky-50 text-[#0284C7] flex items-center justify-center">
                <BookOpen className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-900">
                Mode A: Formative Study Mode
              </h3>
              <p className="text-sm text-slate-600 leading-relaxed">
                Untimed question solving with immediate verification after each submission. Read both the primary synthesis explanation and specific rationales explaining why each distractor (Options A–D) is correct or incorrect.
              </p>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-3">
              <div className="w-9 h-9 rounded-lg bg-amber-50 text-amber-700 flex items-center justify-center">
                <Clock className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-900">
                Mode B: Server-Verified Exam Mode
              </h3>
              <p className="text-sm text-slate-600 leading-relaxed">
                Simulates real examination conditions. Correct answers and explanations are withheld on the server until submission so they cannot be leaked in browser payloads. Includes a server-synchronized timer and question navigator.
              </p>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-3">
              <div className="w-9 h-9 rounded-lg bg-emerald-50 text-emerald-700 flex items-center justify-center">
                <SlidersHorizontal className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-900">
                Mode C: Custom Practice Builder
              </h3>
              <p className="text-sm text-slate-600 leading-relaxed">
                Combine multiple subjects and lectures, filter by difficulty (Easy, Medium, Hard) or topic tags, shuffle question order, shuffle answer-option order with guaranteed key preservation, and prioritize unseen questions.
              </p>
            </div>
          </div>
        </section>

        {/* Student Progress Tracking & Security */}
        <section id="analytics" className="max-w-7xl mx-auto px-6 lg:px-12 py-14">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
            <div className="lg:col-span-7 rounded-xl border border-slate-200 bg-white p-6 space-y-4">
              <div className="flex items-center gap-2 text-xs font-semibold text-[#0284C7]">
                <TrendingUp className="w-4 h-4" />
                <span>Transparent Academic Analytics</span>
              </div>
              <h2 className="text-xl font-bold text-slate-900">
                Track Unique Questions Completed vs. Total Attempts
              </h2>
              <p className="text-sm text-slate-600 leading-relaxed">
                Repeatedly solving the same lecture bank never artificially inflates your curriculum completion rate. MedAtlas MCQ separates unique questions mastered from total answers submitted across every subject and lecture.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 text-xs text-slate-700">
                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                  <p className="font-semibold text-slate-900">
                    Small-Sample Guarded Topic Analysis
                  </p>
                  <p className="text-slate-600">
                    Topics with fewer than 3 attempts are explicitly labeled as Insufficient Sample rather than prematurely flagging a weak area.
                  </p>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                  <p className="font-semibold text-slate-900">
                    Historical Attempt Snapshots
                  </p>
                  <p className="text-slate-600">
                    Completed exams store immutable snapshots of question stems and keys so later curriculum edits never alter your historical scores.
                  </p>
                </div>
              </div>
            </div>

            <div className="lg:col-span-5 rounded-xl border border-slate-200 bg-white p-6 flex flex-col justify-between space-y-4">
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-xs font-semibold text-emerald-700">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Account Privacy &amp; Free Trial Guarantee</span>
                </div>
                <h3 className="text-lg font-bold text-slate-900">
                  100% Free Access During Initial Trial Period
                </h3>
                <p className="text-sm text-slate-600 leading-relaxed">
                  All registered medical students receive unrestricted access to every published subject, lecture, and mock exam during the trial period. Your attempts, bookmarks, and progress metrics are strictly isolated to your authenticated user ID.
                </p>
              </div>
              <button
                type="button"
                onClick={() => openAuth('register')}
                className="w-full py-2.5 px-4 text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
              >
                Register Free Student Account
              </button>
            </div>
          </div>
        </section>
      </main>

      {/* Footer with About, Contact, Privacy Policy, and Terms of Use */}
      <footer className="bg-white border-t border-slate-200 px-6 lg:px-12 py-8">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500">
          <div>
            <span className="font-semibold text-slate-800">MedAtlas MCQ</span> · Lecture-Based Medical Education Platform
          </div>
          <div className="flex flex-wrap items-center gap-6">
            <button
              type="button"
              onClick={() => setLegalModal('about')}
              className="hover:text-slate-900 transition-colors cursor-pointer"
            >
              About
            </button>
            <button
              type="button"
              onClick={() => setLegalModal('contact')}
              className="hover:text-slate-900 transition-colors cursor-pointer"
            >
              Contact
            </button>
            <button
              type="button"
              onClick={() => setLegalModal('privacy')}
              className="hover:text-slate-900 transition-colors cursor-pointer"
            >
              Privacy Policy
            </button>
            <button
              type="button"
              onClick={() => setLegalModal('terms')}
              className="hover:text-slate-900 transition-colors cursor-pointer"
            >
              Terms of Use
            </button>
          </div>
        </div>
      </footer>

      {/* Authentication Modal */}
      {authModalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="auth-dialog-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-xs p-4"
        >
          <div className="w-full max-w-md rounded-xl bg-white border border-slate-200 shadow-lg p-6 space-y-5">
            <div className="flex items-center justify-between">
              <h2 id="auth-dialog-title" className="text-lg font-bold text-slate-900">
                {authTab === 'login'
                  ? 'Sign In to MedAtlas MCQ'
                  : authTab === 'register'
                  ? 'Create Student Account'
                  : 'Reset Account Password'}
              </h2>
              <button
                type="button"
                aria-label="Close authentication dialog"
                onClick={() => setAuthModalOpen(false)}
                className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Interactive Tab Switcher */}
            <div className="grid grid-cols-3 gap-1 p-1 bg-slate-100 rounded-lg text-xs font-medium">
              <button
                type="button"
                onClick={() => {
                  setAuthTab('login');
                  setAuthError(null);
                }}
                className={`py-1.5 rounded-md transition-colors cursor-pointer ${
                  authTab === 'login'
                    ? 'bg-white text-slate-900 shadow-xs font-semibold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => {
                  setAuthTab('register');
                  setAuthError(null);
                }}
                className={`py-1.5 rounded-md transition-colors cursor-pointer ${
                  authTab === 'register'
                    ? 'bg-white text-slate-900 shadow-xs font-semibold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Register
              </button>
              <button
                type="button"
                onClick={() => {
                  setAuthTab('reset');
                  setAuthError(null);
                }}
                className={`py-1.5 rounded-md transition-colors cursor-pointer ${
                  authTab === 'reset'
                    ? 'bg-white text-slate-900 shadow-xs font-semibold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Reset Password
              </button>
            </div>

            {authError && (
              <div
                role="alert"
                className="p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-800"
              >
                {authError}
              </div>
            )}

            {authSuccess && (
              <div
                role="status"
                className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800"
              >
                {authSuccess}
              </div>
            )}

            <form onSubmit={handleEmailAuth} className="space-y-4">
              {authTab === 'register' && (
                <div>
                  <label
                    htmlFor="auth-display-name"
                    className="block text-xs font-semibold text-slate-700 mb-1"
                  >
                    Full Name / Display Name
                  </label>
                  <input
                    id="auth-display-name"
                    type="text"
                    required
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="e.g., Maya Lin, MS2"
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0284C7]"
                  />
                </div>
              )}

              {(authTab !== 'reset' || resetStep === 'request') && (
                <div>
                  <label
                    htmlFor="auth-email"
                    className="block text-xs font-semibold text-slate-700 mb-1"
                  >
                    Academic or Personal Email
                  </label>
                  <input
                    id="auth-email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="student@medschool.edu"
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0284C7]"
                  />
                </div>
              )}

              {authTab === 'reset' && resetStep === 'confirm' && (
                <div>
                  <label
                    htmlFor="auth-recovery-token"
                    className="block text-xs font-semibold text-slate-700 mb-1"
                  >
                    Password Reset Link or Single-Use Recovery Code
                  </label>
                  <input
                    id="auth-recovery-token"
                    type="text"
                    required
                    minLength={10}
                    value={recoveryToken}
                    onChange={(e) => setRecoveryToken(e.target.value)}
                    placeholder="Paste your password reset link or oobCode"
                    className="w-full px-3 py-2 text-sm font-mono-tabular rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0284C7]"
                  />
                </div>
              )}

              {(authTab !== 'reset' || resetStep === 'confirm') && (
                <div>
                  <label
                    htmlFor="auth-password"
                    className="block text-xs font-semibold text-slate-700 mb-1"
                  >
                    {authTab === 'reset' ? 'New Password (8–128 characters)' : 'Password'}
                  </label>
                  <input
                    id="auth-password"
                    type="password"
                    required
                    minLength={8}
                    maxLength={128}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0284C7]"
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={authLoading}
                className="w-full py-2.5 px-4 text-sm font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] disabled:opacity-50 rounded-lg transition-colors cursor-pointer"
              >
                {authLoading
                  ? 'Processing...'
                  : authTab === 'login'
                  ? 'Sign In with Email'
                  : authTab === 'register'
                  ? 'Create Student Account'
                  : resetStep === 'request'
                  ? 'Send Password Reset Email'
                  : 'Verify Token & Update Password'}
              </button>

              {authTab === 'reset' && (
                <div className="flex items-center justify-between text-xs text-slate-600 pt-1">
                  {resetStep === 'request' ? (
                    <button
                      type="button"
                      onClick={() => {
                        setResetStep('confirm');
                        setAuthError(null);
                      }}
                      className="text-[#0284C7] hover:underline font-medium cursor-pointer"
                    >
                      Already have a recovery token? Enter it here →
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() => {
                        setResetStep('request');
                        setAuthError(null);
                      }}
                      className="text-slate-600 hover:text-slate-900 font-medium cursor-pointer"
                    >
                      ← Back to request password reset email
                    </button>
                  )}
                </div>
              )}
            </form>

            <div className="pt-3 border-t border-slate-200">
              <button
                type="button"
                onClick={handleGoogleLogin}
                disabled={authLoading}
                className="w-full py-2.5 px-4 text-xs font-semibold text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-lg transition-colors cursor-pointer"
              >
                Continue with Google Sign-In
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer Information Dialogs (About, Contact, Privacy, Terms) */}
      {legalModal && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-xs p-4"
        >
          <div className="w-full max-w-lg rounded-xl bg-white border border-slate-200 shadow-lg p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-slate-900">
                {legalModal === 'about' && 'About MedAtlas MCQ'}
                {legalModal === 'contact' && 'Contact & Curriculum Support'}
                {legalModal === 'privacy' && 'Privacy Policy & Student Data Protection'}
                {legalModal === 'terms' && 'Terms of Use & Trial Access Policy'}
              </h2>
              <button
                type="button"
                aria-label="Close information dialog"
                onClick={() => setLegalModal(null)}
                className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="text-sm text-slate-600 space-y-3 leading-relaxed">
              {legalModal === 'about' && (
                <>
                  <p>
                    MedAtlas MCQ is a structured medical education platform designed around the Subject → Lecture → Question Bank hierarchy used in pre-clinical and clinical medical curricula.
                  </p>
                  <p>
                    Every multiple-choice question includes a primary synthesis explanation as well as option-by-option rationales for distractors A, B, C, and D so students build rigorous diagnostic reasoning.
                  </p>
                </>
              )}
              {legalModal === 'contact' && (
                <>
                  <p>
                    For curriculum corrections, question-key peer review, or account assistance:
                  </p>
                  <p className="font-mono-tabular text-xs bg-slate-50 p-3 rounded-lg border border-slate-200 text-slate-800">
                    Curriculum Editorial Desk: curriculum@medatlas.edu
                    <br />
                    Technical Support: support@medatlas.edu
                  </p>
                </>
              )}
              {legalModal === 'privacy' && (
                <>
                  <p>
                    <strong>Account Isolation:</strong> All exam sessions, question attempts, accuracy metrics, and bookmarks are strictly scoped to your authenticated user UID at the database level. No student can view or modify another student’s records.
                  </p>
                  <p>
                    <strong>Credential Security:</strong> Passwords are never stored in plaintext. Authentication uses Firebase Auth and scrypt-salted cryptographic hashes.
                  </p>
                  <p>
                    <strong>Right to Erasure:</strong> Students can permanently delete their account and all associated attempt and bookmark records at any time from Profile &amp; Settings.
                  </p>
                </>
              )}
              {legalModal === 'terms' && (
                <>
                  <p>
                    <strong>Free Trial Period:</strong> During the initial trial release, all published subjects, lectures, practice sets, and mock exams are free for all registered students with no payment processing or locked content.
                  </p>
                  <p>
                    <strong>Educational Disclaimer:</strong> Content on MedAtlas MCQ is provided strictly for academic medical examination preparation and does not constitute clinical medical advice or patient-care guidelines.
                  </p>
                </>
              )}
            </div>

            <div className="pt-2 flex justify-end">
              <button
                type="button"
                onClick={() => setLegalModal(null)}
                className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
