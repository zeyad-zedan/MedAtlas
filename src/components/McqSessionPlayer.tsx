import React, { useState, useEffect, useRef } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Bookmark,
  CheckCircle2,
  Clock,
  Flag,
  XCircle,
  AlertTriangle,
  Award,
  RotateCcw,
} from 'lucide-react';
import { api } from '../lib/api.ts';
import { OPTION_KEYS, OptionKey, sanitizeSvgDiagram } from '../lib/mcq-engine.ts';

interface McqSessionPlayerProps {
  initialSession: any;
  shortfallNotice?: string | null;
  onExit: () => void;
  onSessionCompleted: (completedSession: any) => void;
}

export const McqSessionPlayer: React.FC<McqSessionPlayerProps> = ({
  initialSession,
  shortfallNotice,
  onExit,
  onSessionCompleted,
}) => {
  const [session, setSession] = useState<any>(initialSession);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [localSelections, setLocalSelections] = useState<Record<number, OptionKey | null>>(
    () => {
      const map: Record<number, OptionKey | null> = {};
      for (const q of initialSession?.questions || []) {
        map[q.id] = q.selectedDisplayed || null;
      }
      return map;
    }
  );
  const [flaggedIds, setFlaggedIds] = useState<Set<number>>(new Set());
  const [submittingAnswer, setSubmittingAnswer] = useState(false);
  const [completingSession, setCompletingSession] = useState(false);
  const [confirmSubmitModal, setConfirmSubmitModal] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(
    initialSession?.elapsedSeconds || 0
  );
  const [remainingSeconds, setRemainingSeconds] = useState<number | null>(
    initialSession?.remainingSeconds ?? null
  );

  const autoSubmittedRef = useRef(false);

  const isCompleted = session.status === 'completed';
  const isExamMode = session.mode === 'exam';
  const questions = session.questions || [];
  const currentQ = questions[currentIndex] || null;

  // Timer effect for active sessions
  useEffect(() => {
    if (isCompleted) return;
    const interval = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
      if (remainingSeconds !== null) {
        setRemainingSeconds((prev) => {
          if (prev === null) return null;
          if (prev <= 1) {
            return 0;
          }
          return prev - 1;
        });
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [isCompleted, remainingSeconds !== null]);

  // Auto-submit exam if timer reaches 0 in Exam Mode
  useEffect(() => {
    if (
      !isCompleted &&
      isExamMode &&
      remainingSeconds !== null &&
      remainingSeconds <= 0 &&
      !autoSubmittedRef.current
    ) {
      autoSubmittedRef.current = true;
      handleFinishSession(true);
    }
  }, [remainingSeconds, isCompleted, isExamMode]);

  const formatTime = (secs: number) => {
    const mins = Math.floor(secs / 60);
    const rem = secs % 60;
    return `${String(mins).padStart(2, '0')}:${String(rem).padStart(2, '0')}`;
  };

  const handleSelectOption = async (opt: OptionKey) => {
    if (!currentQ || isCompleted) return;
    // In Study/Custom mode, once a question is submitted, lock selection
    if (!isExamMode && currentQ.submitted) return;

    setLocalSelections((prev) => ({ ...prev, [currentQ.id]: opt }));
    setErrorMsg(null);

    // In Exam Mode, persist draft answer immediately so page refreshes never lose answers
    if (isExamMode) {
      try {
        const res = await api.submitQuestionAnswer(
          session.id,
          currentQ.id,
          opt,
          false,
          elapsedSeconds
        );
        setSession(res.session);
      } catch (err: any) {
        setErrorMsg(err.message || 'Failed to save selection.');
      }
    }
  };

  const handleSubmitSingleQuestion = async () => {
    if (!currentQ || isCompleted || isExamMode) return;
    const chosen = localSelections[currentQ.id];
    if (!chosen) {
      setErrorMsg('Please select an answer option (A, B, C, or D) before submitting.');
      return;
    }

    setSubmittingAnswer(true);
    setErrorMsg(null);
    try {
      const res = await api.submitQuestionAnswer(
        session.id,
        currentQ.id,
        chosen,
        true,
        elapsedSeconds
      );
      setSession(res.session);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to submit answer.');
    } finally {
      setSubmittingAnswer(false);
    }
  };

  const handleToggleBookmark = async (questionId: number) => {
    try {
      const res = await api.toggleBookmark(questionId);
      setSession((prev: any) => ({
        ...prev,
        questions: prev.questions.map((q: any) =>
          q.id === questionId ? { ...q, isBookmarked: res.bookmarked } : q
        ),
      }));
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to update bookmark.');
    }
  };

  const handleToggleFlag = (questionId: number) => {
    setFlaggedIds((prev) => {
      const next = new Set(prev);
      if (next.has(questionId)) next.delete(questionId);
      else next.add(questionId);
      return next;
    });
  };

  const handleFinishSession = async (skipConfirm = false) => {
    if (isCompleted || completingSession) return;

    const unansweredCount = questions.filter((q: any) => !localSelections[q.id]).length;
    if (!skipConfirm && unansweredCount > 0 && !confirmSubmitModal) {
      setConfirmSubmitModal(true);
      return;
    }

    setConfirmSubmitModal(false);
    setCompletingSession(true);
    setErrorMsg(null);
    try {
      const res = await api.completeSession(session.id, localSelections, elapsedSeconds);
      setSession(res.session);
      onSessionCompleted(res.session);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to complete session.');
    } finally {
      setCompletingSession(false);
    }
  };

  if (!currentQ) {
    return (
      <div className="max-w-3xl mx-auto p-8 bg-white rounded-xl border border-slate-200 text-center space-y-4">
        <p className="text-base font-semibold text-slate-800">
          This session contains no questions.
        </p>
        <button
          type="button"
          onClick={onExit}
          className="px-4 py-2 text-sm font-semibold text-white bg-[#0284C7] rounded-lg cursor-pointer"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  const selectedOpt = localSelections[currentQ.id] ?? currentQ.selectedDisplayed ?? null;
  const showFeedback = isCompleted || (!isExamMode && currentQ.submitted);
  const correctOpt = currentQ.correctDisplayedOption as OptionKey | undefined;
  const answeredCount = questions.filter(
    (q: any) => Boolean(localSelections[q.id] || q.selectedDisplayed)
  ).length;

  return (
    <div className="space-y-6">
      {/* Top Session Control Header */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 sm:p-5 flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <button
              type="button"
              onClick={onExit}
              className="inline-flex items-center gap-1 font-semibold text-slate-700 hover:text-slate-900 cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Exit to Workspace
            </button>
            <span>·</span>
            <span>
              {session.mode === 'exam'
                ? 'Timed Exam Simulation'
                : session.mode === 'custom'
                ? 'Custom Practice Mode'
                : 'Formative Study Mode'}
            </span>
            {session.shuffleOptions && (
              <>
                <span>·</span>
                <span>Options Shuffled</span>
              </>
            )}
          </div>
          <h1 className="text-lg font-bold text-slate-900">{session.title}</h1>
        </div>

        <div className="flex items-center gap-4">
          {isExamMode && remainingSeconds !== null && !isCompleted ? (
            <div
              className={`px-3.5 py-2 rounded-lg border font-mono-tabular text-sm font-semibold flex items-center gap-2 ${
                remainingSeconds < 60
                  ? 'bg-red-50 border-red-300 text-red-700'
                  : 'bg-amber-50 border-amber-200 text-amber-900'
              }`}
            >
              <Clock className="w-4 h-4" />
              <span>Time Remaining: {formatTime(remainingSeconds)}</span>
            </div>
          ) : (
            <div className="px-3 py-1.5 rounded-lg bg-slate-100 text-slate-700 font-mono-tabular text-xs font-medium flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" />
              <span>Elapsed: {formatTime(elapsedSeconds)}</span>
            </div>
          )}

          {!isCompleted && (
            <button
              type="button"
              onClick={() => handleFinishSession(false)}
              disabled={completingSession}
              className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {completingSession
                ? 'Grading...'
                : isExamMode
                ? 'Submit Exam'
                : 'Finish & Score Session'}
            </button>
          )}
        </div>
      </div>

      {/* Shortfall Notice if requested count exceeded available questions */}
      {shortfallNotice && (
        <div
          role="status"
          className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900 flex items-center gap-2.5"
        >
          <AlertTriangle className="w-4 h-4 shrink-0 text-amber-700" />
          <span>{shortfallNotice}</span>
        </div>
      )}

      {errorMsg && (
        <div
          role="alert"
          className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-xs text-red-800"
        >
          {errorMsg}
        </div>
      )}

      {/* Results Summary Banner when Session is Completed */}
      {isCompleted && (
        <div className="bg-white rounded-xl border border-slate-200 p-6 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-xs font-semibold text-[#0284C7]">
                <Award className="w-4 h-4" />
                <span>Completed Assessment Summary</span>
              </div>
              <h2 className="text-xl font-bold text-slate-900">
                Final Score: {session.scorePercentage}% ({session.correctCount} /{' '}
                {session.totalQuestions} Correct)
              </h2>
            </div>
            <button
              type="button"
              onClick={onExit}
              className="px-4 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Back to Dashboard &amp; Analytics
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 font-mono-tabular">
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
              <p className="text-xs font-sans text-slate-500">Total Questions</p>
              <p className="text-xl font-bold text-slate-900 mt-0.5">
                {session.totalQuestions}
              </p>
            </div>
            <div className="p-3.5 rounded-lg bg-emerald-50/70 border border-emerald-200">
              <p className="text-xs font-sans text-emerald-800">Correct Answers</p>
              <p className="text-xl font-bold text-emerald-700 mt-0.5">
                {session.correctCount}
              </p>
            </div>
            <div className="p-3.5 rounded-lg bg-red-50/70 border border-red-200">
              <p className="text-xs font-sans text-red-800">Incorrect Answers</p>
              <p className="text-xl font-bold text-red-700 mt-0.5">
                {session.incorrectCount}
              </p>
            </div>
            <div className="p-3.5 rounded-lg bg-amber-50/70 border border-amber-200">
              <p className="text-xs font-sans text-amber-800">Unanswered</p>
              <p className="text-xl font-bold text-amber-700 mt-0.5">
                {session.unansweredCount}
              </p>
            </div>
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
              <p className="text-xs font-sans text-slate-500">Time Taken</p>
              <p className="text-xl font-bold text-slate-900 mt-0.5">
                {formatTime(session.elapsedSeconds || elapsedSeconds)}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Main Two-Zone Question Stage + Question Navigator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left/Center Zone: Question Vignette, Options, and Explanation */}
        <div className="lg:col-span-8 bg-white rounded-xl border border-slate-200 p-6 space-y-6">
          {/* Question Metadata Bar (Clean unboxed text per Zero-Pill Discipline) */}
          <div className="flex flex-wrap items-center justify-between gap-2 pb-4 border-b border-slate-100 text-xs text-slate-500">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono-tabular font-semibold text-slate-900">
                Question {currentIndex + 1} of {questions.length}
              </span>
              <span>·</span>
              <span>{currentQ.subjectTitle}</span>
              <span>·</span>
              <span>{currentQ.lectureTitle}</span>
              <span>·</span>
              <span>Difficulty: {currentQ.difficulty}</span>
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => handleToggleFlag(currentQ.id)}
                className={`inline-flex items-center gap-1 text-xs font-medium cursor-pointer ${
                  flaggedIds.has(currentQ.id)
                    ? 'text-amber-700 font-semibold'
                    : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                <Flag className="w-3.5 h-3.5" />
                {flaggedIds.has(currentQ.id) ? 'Flagged' : 'Flag for Review'}
              </button>

              <button
                type="button"
                onClick={() => handleToggleBookmark(currentQ.id)}
                className={`inline-flex items-center gap-1 text-xs font-medium cursor-pointer ${
                  currentQ.isBookmarked
                    ? 'text-[#0284C7] font-semibold'
                    : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                <Bookmark className="w-3.5 h-3.5" />
                {currentQ.isBookmarked ? 'Bookmarked' : 'Bookmark'}
              </button>
            </div>
          </div>

          {/* Question Vignette Text */}
          <div className="space-y-4">
            <p className="text-base sm:text-[17px] font-serif-academic text-slate-900 leading-[1.7]">
              {currentQ.questionText}
            </p>

            {/* Optional Scientific / Histological SVG Diagram */}
            {currentQ.diagramSvg && (
              <div
                className="my-4"
                dangerouslySetInnerHTML={{
                  __html: sanitizeSvgDiagram(currentQ.diagramSvg),
                }}
              />
            )}
          </div>

          {/* Four Answer Options (A, B, C, D) */}
          <div className="space-y-3" role="radiogroup" aria-label="Answer Options">
            {OPTION_KEYS.map((letter) => {
              const optionText = currentQ.options?.[letter] || '';
              const isSelected = selectedOpt === letter;
              const isCorrectOption = showFeedback && correctOpt === letter;
              const isWrongSelection =
                showFeedback && isSelected && correctOpt !== letter;

              let borderStyle = 'border-slate-200 hover:border-slate-300 bg-white';
              let statusLabel: React.ReactNode = null;

              if (showFeedback) {
                if (isCorrectOption) {
                  borderStyle = 'border-emerald-600 bg-emerald-50/70 text-emerald-950';
                  statusLabel = (
                    <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 whitespace-nowrap shrink-0">
                      <CheckCircle2 className="w-4 h-4" />
                      Correct Answer
                    </span>
                  );
                } else if (isWrongSelection) {
                  borderStyle = 'border-red-500 bg-red-50/70 text-red-950';
                  statusLabel = (
                    <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 whitespace-nowrap shrink-0">
                      <XCircle className="w-4 h-4" />
                      Your Answer (Incorrect)
                    </span>
                  );
                } else {
                  borderStyle = 'border-slate-200 bg-slate-50/50 text-slate-600';
                }
              } else if (isSelected) {
                borderStyle = 'border-[#0284C7] bg-sky-50/60 text-slate-900 ring-1 ring-[#0284C7]';
                statusLabel = (
                  <span className="text-xs font-semibold text-[#0284C7] whitespace-nowrap shrink-0">
                    Selected
                  </span>
                );
              }

              const optionExplanation =
                showFeedback && currentQ.optionExplanations?.[letter];

              return (
                <div
                  key={letter}
                  className={`rounded-xl border p-4 transition-colors ${borderStyle}`}
                >
                  <button
                    type="button"
                    disabled={showFeedback}
                    onClick={() => handleSelectOption(letter)}
                    className="w-full text-left flex items-start justify-between gap-4 cursor-pointer disabled:cursor-default"
                  >
                    <div className="flex items-start gap-3">
                      <span
                        className={`w-7 h-7 rounded-lg font-mono-tabular text-xs font-bold flex items-center justify-center shrink-0 mt-0.5 ${
                          isSelected
                            ? 'bg-[#0284C7] text-white'
                            : 'bg-slate-100 text-slate-700'
                        }`}
                      >
                        {letter}
                      </span>
                      <span className="text-sm sm:text-[15px] leading-relaxed">
                        {optionText}
                      </span>
                    </div>
                    {statusLabel}
                  </button>

                  {optionExplanation && (
                    <p className="mt-2.5 pt-2.5 border-t border-slate-200/80 text-xs text-slate-600 leading-relaxed pl-10">
                      <span className="font-semibold text-slate-800">
                        Option {letter} Rationale:{' '}
                      </span>
                      {optionExplanation}
                    </p>
                  )}
                </div>
              );
            })}
          </div>

          {/* Submit Answer Button (Study & Custom Modes) or Active Exam Notice */}
          {!isCompleted && !isExamMode && !currentQ.submitted && (
            <div className="pt-2 flex items-center justify-between gap-4">
              <p className="text-xs text-slate-500">
                Select one option and submit to view immediate feedback and explanations.
              </p>
              <button
                type="button"
                onClick={handleSubmitSingleQuestion}
                disabled={!selectedOpt || submittingAnswer}
                className="px-5 py-2.5 text-sm font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] disabled:opacity-50 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                {submittingAnswer ? 'Checking...' : 'Submit Answer'}
              </button>
            </div>
          )}

          {!isCompleted && isExamMode && (
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 flex items-center justify-between">
              <span>
                Exam Mode Active: Correct answers and explanations are locked on the server until you submit the exam.
              </span>
              <span className="font-mono-tabular font-semibold text-slate-800">
                {selectedOpt ? `Saved choice: ${selectedOpt}` : 'Not answered yet'}
              </span>
            </div>
          )}

          {/* Comprehensive Explanation Box (Visible in Study Mode after submit, or in Exam Mode after completion) */}
          {showFeedback && currentQ.explanation && (
            <div className="rounded-xl bg-slate-50 border border-slate-200 p-5 space-y-2.5">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-900">
                  Core Educational Explanation (Correct Answer: Option {correctOpt})
                </h3>
                {currentQ.tags && (
                  <span className="text-xs text-slate-500">
                    Topics: {currentQ.tags.split(',').join(' · ')}
                  </span>
                )}
              </div>
              <p className="text-sm text-slate-700 leading-relaxed">
                {currentQ.explanation}
              </p>
            </div>
          )}

          {/* Previous / Next Navigation Bar */}
          <div className="pt-4 border-t border-slate-200 flex items-center justify-between gap-4">
            <button
              type="button"
              onClick={() => setCurrentIndex((i) => Math.max(0, i - 1))}
              disabled={currentIndex === 0}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 disabled:opacity-40 rounded-lg transition-colors cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              Previous Question
            </button>

            <span className="text-xs font-mono-tabular text-slate-500">
              {answeredCount} of {questions.length} Answered
            </span>

            {currentIndex < questions.length - 1 ? (
              <button
                type="button"
                onClick={() =>
                  setCurrentIndex((i) => Math.min(questions.length - 1, i + 1))
                }
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg transition-colors cursor-pointer"
              >
                Next Question
                <ArrowRight className="w-4 h-4" />
              </button>
            ) : !isCompleted ? (
              <button
                type="button"
                onClick={() => handleFinishSession(false)}
                disabled={completingSession}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg transition-colors cursor-pointer"
              >
                {completingSession ? 'Submitting...' : 'Finish & View Score'}
              </button>
            ) : (
              <button
                type="button"
                onClick={onExit}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors cursor-pointer"
              >
                Done Reviewing
              </button>
            )}
          </div>
        </div>

        {/* Right Zone: Question Navigator & Session Status */}
        <div className="lg:col-span-4 bg-white rounded-xl border border-slate-200 p-5 space-y-5">
          <div>
            <h2 className="text-sm font-bold text-slate-900">Question Navigator</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Jump directly to any question in this session.
            </p>
          </div>

          <div className="grid grid-cols-5 gap-2">
            {questions.map((q: any, idx: number) => {
              const chosen = localSelections[q.id] ?? q.selectedDisplayed ?? null;
              const isCurrent = idx === currentIndex;
              const isFlagged = flaggedIds.has(q.id);
              const qFeedback = isCompleted || (!isExamMode && q.submitted);

              let btnClass =
                'bg-slate-100 text-slate-700 border-slate-200 hover:bg-slate-200';
              if (qFeedback) {
                if (chosen && chosen === q.correctDisplayedOption) {
                  btnClass = 'bg-emerald-100 text-emerald-900 border-emerald-400 font-bold';
                } else if (chosen && chosen !== q.correctDisplayedOption) {
                  btnClass = 'bg-red-100 text-red-900 border-red-400 font-bold';
                } else {
                  btnClass = 'bg-amber-100 text-amber-900 border-amber-300';
                }
              } else if (chosen) {
                btnClass = 'bg-sky-100 text-[#0369A1] border-sky-300 font-semibold';
              }

              if (isCurrent) {
                btnClass += ' ring-2 ring-slate-900';
              }

              return (
                <button
                  key={q.id}
                  type="button"
                  aria-label={`Go to question ${idx + 1}`}
                  onClick={() => setCurrentIndex(idx)}
                  className={`relative h-10 rounded-lg border font-mono-tabular text-xs transition-all cursor-pointer ${btnClass}`}
                >
                  {idx + 1}
                  {isFlagged && (
                    <span
                      title="Flagged for review"
                      className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-amber-500"
                    />
                  )}
                </button>
              );
            })}
          </div>

          <div className="pt-4 border-t border-slate-100 space-y-2 text-xs text-slate-600">
            <div className="flex items-center justify-between font-mono-tabular">
              <span className="font-sans">Answered:</span>
              <span className="font-semibold text-slate-900">
                {answeredCount} / {questions.length}
              </span>
            </div>
            <div className="flex items-center justify-between font-mono-tabular">
              <span className="font-sans">Remaining Unanswered:</span>
              <span className="font-semibold text-slate-900">
                {questions.length - answeredCount}
              </span>
            </div>
            <div className="flex items-center justify-between font-mono-tabular">
              <span className="font-sans">Flagged for Review:</span>
              <span className="font-semibold text-slate-900">{flaggedIds.size}</span>
            </div>
          </div>

          {!isCompleted && (
            <button
              type="button"
              onClick={() => handleFinishSession(false)}
              disabled={completingSession}
              className="w-full py-2.5 px-4 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
            >
              {isExamMode ? 'Submit Final Exam' : 'Complete Session & View Summary'}
            </button>
          )}
        </div>
      </div>

      {/* Confirmation Dialog if Unanswered Questions Remain */}
      {confirmSubmitModal && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-xs p-4"
        >
          <div className="w-full max-w-md rounded-xl bg-white border border-slate-200 shadow-lg p-6 space-y-4">
            <div className="flex items-center gap-2.5 text-amber-700">
              <AlertTriangle className="w-5 h-5 shrink-0" />
              <h3 className="text-base font-bold text-slate-900">
                Unanswered Questions Remaining
              </h3>
            </div>
            <p className="text-sm text-slate-600 leading-relaxed">
              You have{' '}
              <strong className="font-mono-tabular text-slate-900">
                {questions.length - answeredCount}
              </strong>{' '}
              unanswered question(s) in this session. Unanswered questions are scored as incorrect upon final submission. Do you want to submit now?
            </p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setConfirmSubmitModal(false)}
                className="px-4 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer"
              >
                Return to Questions
              </button>
              <button
                type="button"
                onClick={() => handleFinishSession(true)}
                className="px-4 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg cursor-pointer"
              >
                Confirm &amp; Submit Now
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
