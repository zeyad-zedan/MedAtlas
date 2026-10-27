import React, { useState } from 'react';
import {
  BookOpen,
  Bookmark,
  CheckCircle2,
  Clock,
  Play,
  SlidersHorizontal,
  TrendingUp,
  AlertTriangle,
  History,
  User,
  Trash2,
  FileText,
  XCircle,
} from 'lucide-react';
import { api, type UserProfile } from '../lib/api.ts';

// ============================================================================
// 1. STUDENT DASHBOARD & ANALYTICS VIEW
// ============================================================================
export const DashboardView: React.FC<{
  dashboardData: any;
  loading: boolean;
  onStartQuickSession: (params: any) => void;
  onOpenSession: (sessionId: number) => void;
  onNavigateTab: (tab: string) => void;
}> = ({
  dashboardData,
  loading,
  onStartQuickSession,
  onOpenSession,
  onNavigateTab,
}) => {
  if (loading || !dashboardData) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((n) => (
            <div
              key={n}
              className="h-28 bg-white rounded-xl border border-slate-200 p-5 animate-pulse"
            />
          ))}
        </div>
        <div className="h-64 bg-white rounded-xl border border-slate-200 p-6 animate-pulse" />
      </div>
    );
  }

  const { summary, subjectProgress = [], topicPerformance = [], history = [] } =
    dashboardData;

  return (
    <div className="space-y-8">
      {/* Header & Primary Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">
            Academic Performance Dashboard
          </h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Live database statistics tracking unique questions completed, total answers submitted, and topic mastery.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => onNavigateTab('practice')}
            className="px-4 py-2 text-xs font-semibold text-slate-800 bg-white border border-slate-300 hover:bg-slate-50 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Custom Practice
          </button>
          <button
            type="button"
            onClick={() =>
              onStartQuickSession({
                mode: 'study',
                title: 'Daily Mixed Medical Study Block',
                requestedCount: 5,
                shuffleQuestions: true,
                avoidRecent: true,
              })
            }
            className="px-4 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Start 5-MCQ Study Block
          </button>
        </div>
      </div>

      {/* Summary KPI Grid (All tabular numerals) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 font-mono-tabular">
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <p className="text-xs font-sans text-slate-500">Completed Attempts</p>
          <p className="text-2xl font-bold text-slate-900 mt-1">
            {summary.totalCompletedAttempts}
          </p>
          <p className="text-xs font-sans text-slate-500 mt-1">
            {summary.inProgressCount} session(s) in progress
          </p>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <p className="text-xs font-sans text-slate-500">
            Unique Questions / Total Answers
          </p>
          <p className="text-2xl font-bold text-slate-900 mt-1">
            {summary.uniqueQuestionsAttempted} / {summary.totalPublishedQuestions}
          </p>
          <p className="text-xs font-sans text-slate-500 mt-1">
            {summary.totalQuestionsAnswered} total answers submitted
          </p>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <p className="text-xs font-sans text-slate-500">Overall Accuracy</p>
          <p className="text-2xl font-bold text-[#0284C7] mt-1">
            {summary.overallAccuracy}%
          </p>
          <p className="text-xs font-sans text-slate-500 mt-1">
            Across {summary.lecturesAttemptedCount} of {summary.totalPublishedLectures} lectures
          </p>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <p className="text-xs font-sans text-slate-500">Bookmarked Questions</p>
          <p className="text-2xl font-bold text-slate-900 mt-1">
            {summary.bookmarkCount}
          </p>
          <button
            type="button"
            onClick={() => onNavigateTab('bookmarks')}
            className="text-xs font-sans font-semibold text-[#0284C7] hover:underline mt-1 cursor-pointer"
          >
            Review Bookmarks →
          </button>
        </div>
      </div>

      {/* Subject & Lecture Progress Breakdown */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-bold text-slate-900">
              Progress by Subject &amp; Lecture
            </h2>
            <p className="text-xs text-slate-500">
              Distinguishes unique questions completed from total answers submitted across repeated sessions.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onNavigateTab('subjects')}
            className="text-xs font-semibold text-[#0284C7] hover:text-[#0369A1] cursor-pointer"
          >
            Browse All Subjects →
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500">
                <th className="py-2.5 pr-4 font-semibold">Subject / Lecture</th>
                <th className="py-2.5 px-3 font-semibold text-right">
                  Unique Completed
                </th>
                <th className="py-2.5 px-3 font-semibold text-right">
                  Total Answers Submitted
                </th>
                <th className="py-2.5 px-3 font-semibold text-right">Accuracy</th>
                <th className="py-2.5 pl-3 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {subjectProgress.map((subj: any) => (
                <React.Fragment key={subj.subjectId}>
                  <tr className="bg-slate-50/80 font-semibold text-slate-900">
                    <td className="py-2.5 pr-4">{subj.title}</td>
                    <td className="py-2.5 px-3 text-right font-mono-tabular">
                      {subj.uniqueQuestionsAttempted} / {subj.totalPublishedQuestions}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono-tabular">
                      {subj.totalAnswersSubmitted}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono-tabular">
                      {subj.totalAnswersSubmitted > 0
                        ? `${subj.accuracyPercentage}%`
                        : '—'}
                    </td>
                    <td className="py-2.5 pl-3 text-right">
                      <button
                        type="button"
                        onClick={() =>
                          onStartQuickSession({
                            mode: 'study',
                            subjectIds: [subj.subjectId],
                            title: `${subj.title} — Subject Study`,
                          })
                        }
                        className="text-[#0284C7] hover:underline font-semibold cursor-pointer"
                      >
                        Practice Subject
                      </button>
                    </td>
                  </tr>
                  {subj.lectures.map((lect: any) => (
                    <tr key={lect.lectureId} className="hover:bg-slate-50/50 text-slate-700">
                      <td className="py-2 pr-4 pl-5">{lect.title}</td>
                      <td className="py-2 px-3 text-right font-mono-tabular">
                        {lect.uniqueQuestionsAttempted} / {lect.totalPublishedQuestions}
                      </td>
                      <td className="py-2 px-3 text-right font-mono-tabular">
                        {lect.totalAnswersSubmitted}
                      </td>
                      <td className="py-2 px-3 text-right font-mono-tabular">
                        {lect.totalAnswersSubmitted > 0
                          ? `${lect.accuracyPercentage}%`
                          : '—'}
                      </td>
                      <td className="py-2 pl-3 text-right">
                        <button
                          type="button"
                          onClick={() =>
                            onStartQuickSession({
                              mode: 'study',
                              lectureIds: [lect.lectureId],
                              title: `${lect.title} — Study Session`,
                            })
                          }
                          className="text-slate-600 hover:text-slate-900 font-medium cursor-pointer"
                        >
                          Solve MCQs
                        </button>
                      </td>
                    </tr>
                  ))}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Weak-Topic Analysis & Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-6 bg-white rounded-xl border border-slate-200 p-6 space-y-4">
          <div>
            <h2 className="text-base font-bold text-slate-900">
              Topic Performance &amp; Weak-Area Analysis
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Topics with fewer than 3 attempts are marked as Insufficient Sample to avoid premature weak-topic labeling.
            </p>
          </div>

          {topicPerformance.length === 0 ? (
            <div className="p-6 rounded-lg bg-slate-50 text-center text-xs text-slate-500">
              Complete at least one practice or exam session to generate topic-level accuracy metrics.
            </div>
          ) : (
            <div className="space-y-3">
              {topicPerformance.slice(0, 8).map((item: any) => (
                <div
                  key={item.topic}
                  className="p-3 rounded-lg border border-slate-200 flex items-center justify-between gap-4 text-xs"
                >
                  <div className="space-y-0.5">
                    <p className="font-semibold text-slate-900">{item.topic}</p>
                    <p className="text-slate-500 font-mono-tabular">
                      {item.correctAttempts} / {item.totalAttempts} correct ({item.uniqueQuestionsAttempted} unique MCQs)
                    </p>
                  </div>
                  <div className="text-right font-mono-tabular shrink-0">
                    <p className="font-bold text-slate-900">{item.accuracyPercentage}%</p>
                    <p
                      className={`font-sans text-[11px] font-semibold ${
                        item.classification === 'Needs Review'
                          ? 'text-red-700'
                          : item.classification === 'Strong'
                          ? 'text-emerald-700'
                          : item.classification === 'Developing'
                          ? 'text-amber-700'
                          : 'text-slate-500'
                      }`}
                    >
                      {item.isSmallSample
                        ? 'Insufficient Sample (<3)'
                        : item.classification}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Exam & Practice Sessions */}
        <div className="lg:col-span-6 bg-white rounded-xl border border-slate-200 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-slate-900">
                Recent Sessions &amp; Exam Results
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Open any completed attempt to review your answers or resume an interrupted session.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab('progress')}
              className="text-xs font-semibold text-[#0284C7] hover:underline cursor-pointer"
            >
              Full History →
            </button>
          </div>

          {history.length === 0 ? (
            <div className="p-6 rounded-lg bg-slate-50 text-center text-xs text-slate-500">
              No sessions recorded yet. Start a Study or Exam session to track your history.
            </div>
          ) : (
            <div className="space-y-3">
              {history.slice(0, 5).map((sess: any) => (
                <div
                  key={sess.id}
                  className="p-3.5 rounded-lg border border-slate-200 flex items-center justify-between gap-4 text-xs"
                >
                  <div className="space-y-0.5">
                    <p className="font-semibold text-slate-900">{sess.title}</p>
                    <p className="text-slate-500">
                      Mode: {sess.mode.toUpperCase()} · {sess.totalQuestions} MCQs ·{' '}
                      {new Date(sess.startedAt).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {sess.status === 'completed' ? (
                      <span className="font-mono-tabular font-bold text-slate-900">
                        {sess.scorePercentage}% ({sess.correctCount}/{sess.totalQuestions})
                      </span>
                    ) : (
                      <span className="text-amber-700 font-semibold">In Progress</span>
                    )}
                    <button
                      type="button"
                      onClick={() => onOpenSession(sess.id)}
                      className="px-3 py-1.5 font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-md cursor-pointer"
                    >
                      {sess.status === 'completed' ? 'Review' : 'Resume'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// 2. SUBJECTS & LECTURES BROWSER VIEW
// ============================================================================
export const SubjectsAndLecturesView: React.FC<{
  catalog: any;
  initialSelectedSubjectId?: number | null;
  onStartSession: (params: any) => void;
}> = ({ catalog, initialSelectedSubjectId, onStartSession }) => {
  const subjects = catalog?.subjects || [];
  const [selectedSubjectId, setSelectedSubjectId] = useState<number | 'all'>(
    initialSelectedSubjectId || 'all'
  );
  const [expandedNotesLectureId, setExpandedNotesLectureId] = useState<number | null>(
    null
  );

  const visibleSubjects =
    selectedSubjectId === 'all'
      ? subjects
      : subjects.filter((s: any) => s.id === selectedSubjectId);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">
            Subjects, Lectures &amp; Question Banks
          </h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Select a subject or lecture to read high-yield study notes, solve practice MCQs, or launch a timed mock exam.
          </p>
        </div>

        {/* Interactive Subject Filter Controls */}
        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-200/70 rounded-lg">
          <button
            type="button"
            onClick={() => setSelectedSubjectId('all')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
              selectedSubjectId === 'all'
                ? 'bg-white text-slate-900 shadow-xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            All Subjects ({subjects.length})
          </button>
          {subjects.map((s: any) => (
            <button
              key={s.id}
              type="button"
              onClick={() => setSelectedSubjectId(s.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                selectedSubjectId === s.id
                  ? 'bg-white text-slate-900 shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {s.title}
            </button>
          ))}
        </div>
      </div>

      {visibleSubjects.length === 0 ? (
        <div className="bg-white rounded-xl border border-slate-200 p-8 text-center text-sm text-slate-600">
          No published subjects found.
        </div>
      ) : (
        <div className="space-y-6">
          {visibleSubjects.map((subject: any) => (
            <div
              key={subject.id}
              className="bg-white rounded-xl border border-slate-200 p-6 space-y-5"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100">
                <div className="space-y-1">
                  <div className="text-xs text-slate-500 font-mono-tabular">
                    Subject Module · {subject.lectureCount} Lectures ·{' '}
                    {subject.questionCount} Published MCQs
                  </div>
                  <h2 className="text-xl font-bold text-slate-900">{subject.title}</h2>
                  <p className="text-sm text-slate-600">{subject.description}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() =>
                      onStartSession({
                        mode: 'study',
                        subjectIds: [subject.id],
                        title: `${subject.title} — Comprehensive Study`,
                      })
                    }
                    className="px-3.5 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg cursor-pointer"
                  >
                    Study All Subject MCQs
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      onStartSession({
                        mode: 'exam',
                        subjectIds: [subject.id],
                        title: `${subject.title} — Subject Mock Exam`,
                        shuffleQuestions: true,
                        shuffleOptions: true,
                      })
                    }
                    className="px-3.5 py-2 text-xs font-semibold text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer"
                  >
                    Subject Mock Exam
                  </button>
                </div>
              </div>

              {/* Lectures List inside Subject */}
              <div className="divide-y divide-slate-100">
                {(subject.lectures || []).map((lect: any) => {
                  const notesOpen = expandedNotesLectureId === lect.id;
                  return (
                    <div key={lect.id} className="py-4 first:pt-0 last:pb-0 space-y-3">
                      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                        <div className="space-y-1">
                          <div className="text-xs text-slate-500 font-mono-tabular">
                            Lecture {lect.lectureNumber} · {lect.questionCount} MCQs · Easy:{' '}
                            {lect.difficultyBreakdown?.Easy || 0} / Medium:{' '}
                            {lect.difficultyBreakdown?.Medium || 0} / Hard:{' '}
                            {lect.difficultyBreakdown?.Hard || 0}
                          </div>
                          <h3 className="text-base font-bold text-slate-900">
                            {lect.title}
                          </h3>
                          <p className="text-xs text-slate-600 leading-relaxed">
                            {lect.description}
                          </p>
                        </div>

                        <div className="flex flex-wrap items-center gap-2 shrink-0">
                          {lect.educationalNotes && (
                            <button
                              type="button"
                              onClick={() =>
                                setExpandedNotesLectureId(notesOpen ? null : lect.id)
                              }
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-lg cursor-pointer"
                            >
                              <FileText className="w-3.5 h-3.5" />
                              {notesOpen ? 'Hide Lecture Notes' : 'Read Lecture Notes'}
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() =>
                              onStartSession({
                                mode: 'study',
                                lectureIds: [lect.id],
                                title: `${lect.title} — Study Mode`,
                              })
                            }
                            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg cursor-pointer"
                          >
                            <Play className="w-3.5 h-3.5" />
                            Study Mode ({lect.questionCount})
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              onStartSession({
                                mode: 'exam',
                                lectureIds: [lect.id],
                                title: `${lect.title} — Timed Mock Exam`,
                                shuffleQuestions: true,
                                timeLimitMinutes: 10,
                              })
                            }
                            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer"
                          >
                            <Clock className="w-3.5 h-3.5" />
                            Mock Exam
                          </button>
                        </div>
                      </div>

                      {notesOpen && lect.educationalNotes && (
                        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-700 whitespace-pre-line leading-relaxed">
                          <p className="font-bold text-slate-900 mb-1.5">
                            Lecture Summary &amp; High-Yield Notes:
                          </p>
                          {lect.educationalNotes}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 3. CUSTOM PRACTICE BUILDER VIEW (MODE C)
// ============================================================================
export const CustomPracticeView: React.FC<{
  catalog: any;
  onStartSession: (params: any) => void;
}> = ({ catalog, onStartSession }) => {
  const subjects = catalog?.subjects || [];
  const allLectures = catalog?.lectures || [];

  const [selectedSubjectIds, setSelectedSubjectIds] = useState<number[]>([]);
  const [selectedLectureIds, setSelectedLectureIds] = useState<number[]>([]);
  const [selectedDifficulties, setSelectedDifficulties] = useState<string[]>([]);
  const [tagFilter, setTagFilter] = useState('');
  const [questionCount, setQuestionCount] = useState(5);
  const [shuffleQuestions, setShuffleQuestions] = useState(true);
  const [shuffleOptions, setShuffleOptions] = useState(true);
  const [avoidRecent, setAvoidRecent] = useState(true);
  const [sessionMode, setSessionMode] = useState<'custom' | 'exam'>('custom');

  const toggleItem = <T,>(list: T[], val: T, setter: (next: T[]) => void) => {
    if (list.includes(val)) setter(list.filter((x) => x !== val));
    else setter([...list, val]);
  };

  const filteredLectures =
    selectedSubjectIds.length === 0
      ? allLectures
      : allLectures.filter((l: any) => selectedSubjectIds.includes(l.subjectId));

  const handleLaunchCustom = (e: React.FormEvent) => {
    e.preventDefault();
    onStartSession({
      mode: sessionMode,
      title:
        sessionMode === 'exam'
          ? `Custom Timed Exam (${questionCount} MCQs)`
          : `Custom Practice Session (${questionCount} MCQs)`,
      subjectIds: selectedSubjectIds.length > 0 ? selectedSubjectIds : undefined,
      lectureIds: selectedLectureIds.length > 0 ? selectedLectureIds : undefined,
      difficulties: selectedDifficulties.length > 0 ? selectedDifficulties : undefined,
      tagFilter: tagFilter.trim() || undefined,
      requestedCount: Number(questionCount) || 5,
      shuffleQuestions,
      shuffleOptions,
      avoidRecent,
    });
  };

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">
          Custom Practice &amp; Question Filter Builder
        </h1>
        <p className="text-sm text-slate-600 mt-0.5">
          Configure a tailored question set across multiple subjects, lectures, difficulties, and shuffling rules.
        </p>
      </div>

      <form
        onSubmit={handleLaunchCustom}
        className="bg-white rounded-xl border border-slate-200 p-6 space-y-6"
      >
        {/* 1. Select Subjects */}
        <div className="space-y-2">
          <label className="block text-xs font-bold text-slate-900">
            1. Select Subjects (Leave unselected to include all subjects)
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {subjects.map((s: any) => {
              const active = selectedSubjectIds.includes(s.id);
              return (
                <button
                  key={s.id}
                  type="button"
                  onClick={() =>
                    toggleItem(selectedSubjectIds, s.id, setSelectedSubjectIds)
                  }
                  className={`p-3 rounded-lg border text-left text-xs transition-colors flex items-center justify-between cursor-pointer ${
                    active
                      ? 'border-[#0284C7] bg-sky-50/70 text-slate-900 font-semibold'
                      : 'border-slate-200 hover:border-slate-300 text-slate-700'
                  }`}
                >
                  <span>{s.title}</span>
                  <span className="font-mono-tabular text-slate-500">
                    {s.questionCount} MCQs
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* 2. Select Specific Lectures */}
        <div className="space-y-2">
          <label className="block text-xs font-bold text-slate-900">
            2. Filter by Specific Lectures (Optional)
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-52 overflow-y-auto p-1">
            {filteredLectures.map((l: any) => {
              const active = selectedLectureIds.includes(l.id);
              return (
                <button
                  key={l.id}
                  type="button"
                  onClick={() =>
                    toggleItem(selectedLectureIds, l.id, setSelectedLectureIds)
                  }
                  className={`p-2.5 rounded-lg border text-left text-xs transition-colors flex items-center justify-between cursor-pointer ${
                    active
                      ? 'border-[#0284C7] bg-sky-50/70 text-slate-900 font-semibold'
                      : 'border-slate-200 hover:border-slate-300 text-slate-600'
                  }`}
                >
                  <span className="truncate pr-2">{l.title}</span>
                  <span className="font-mono-tabular shrink-0">
                    {l.questionCount} MCQs
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* 3. Difficulty, Question Count & Topic Filter */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="space-y-2">
            <label className="block text-xs font-bold text-slate-900">
              3. Difficulty Level
            </label>
            <div className="flex items-center gap-1.5">
              {['Easy', 'Medium', 'Hard'].map((diff) => {
                const active = selectedDifficulties.includes(diff);
                return (
                  <button
                    key={diff}
                    type="button"
                    onClick={() =>
                      toggleItem(
                        selectedDifficulties,
                        diff,
                        setSelectedDifficulties
                      )
                    }
                    className={`flex-1 py-2 text-xs font-semibold rounded-lg border transition-colors cursor-pointer ${
                      active
                        ? 'border-[#0284C7] bg-[#0284C7] text-white'
                        : 'border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100'
                    }`}
                  >
                    {diff}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="space-y-2">
            <label
              htmlFor="custom-question-count"
              className="block text-xs font-bold text-slate-900"
            >
              4. Number of Questions: <span className="font-mono-tabular">{questionCount}</span>
            </label>
            <input
              id="custom-question-count"
              type="number"
              min={1}
              max={100}
              value={questionCount}
              onChange={(e) => setQuestionCount(Number(e.target.value))}
              className="w-full px-3 py-2 text-sm font-mono-tabular rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0284C7]"
            />
          </div>

          <div className="space-y-2">
            <label
              htmlFor="custom-topic-tag"
              className="block text-xs font-bold text-slate-900"
            >
              5. Topic Keyword (Optional)
            </label>
            <input
              id="custom-topic-tag"
              type="text"
              value={tagFilter}
              onChange={(e) => setTagFilter(e.target.value)}
              placeholder="e.g., Collagen, GFR, Necrosis"
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0284C7]"
            />
          </div>
        </div>

        {/* 4. Randomization & Feedback Rules */}
        <div className="pt-4 border-t border-slate-100 grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <label className="flex items-center gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={shuffleQuestions}
              onChange={(e) => setShuffleQuestions(e.target.checked)}
              className="rounded border-slate-300 text-[#0284C7]"
            />
            <span className="font-medium text-slate-800">
              Shuffle question order randomly
            </span>
          </label>

          <label className="flex items-center gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={shuffleOptions}
              onChange={(e) => setShuffleOptions(e.target.checked)}
              className="rounded border-slate-300 text-[#0284C7]"
            />
            <span className="font-medium text-slate-800">
              Shuffle answer options (A–D) while preserving correct answer key
            </span>
          </label>

          <label className="flex items-center gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={avoidRecent}
              onChange={(e) => setAvoidRecent(e.target.checked)}
              className="rounded border-slate-300 text-[#0284C7]"
            />
            <span className="font-medium text-slate-800">
              Avoid recently answered questions when alternatives exist
            </span>
          </label>

          <div className="flex items-center gap-3">
            <span className="font-semibold text-slate-800">Delivery Mode:</span>
            <button
              type="button"
              onClick={() => setSessionMode('custom')}
              className={`px-2.5 py-1 rounded-md font-semibold cursor-pointer ${
                sessionMode === 'custom'
                  ? 'bg-[#0284C7] text-white'
                  : 'bg-slate-100 text-slate-600'
              }`}
            >
              Immediate Study Feedback
            </button>
            <button
              type="button"
              onClick={() => setSessionMode('exam')}
              className={`px-2.5 py-1 rounded-md font-semibold cursor-pointer ${
                sessionMode === 'exam'
                  ? 'bg-slate-900 text-white'
                  : 'bg-slate-100 text-slate-600'
              }`}
            >
              Timed Exam Mode
            </button>
          </div>
        </div>

        <div className="pt-2 flex justify-end">
          <button
            type="submit"
            className="px-6 py-2.5 text-sm font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg transition-colors cursor-pointer"
          >
            Launch Custom Question Set
          </button>
        </div>
      </form>
    </div>
  );
};

// ============================================================================
// 4. MOCK EXAMS SIMULATION CENTER (MODE B)
// ============================================================================
export const MockExamsView: React.FC<{
  catalog: any;
  dashboardData: any;
  onStartSession: (params: any) => void;
  onOpenSession: (sessionId: number) => void;
}> = ({ catalog, dashboardData, onStartSession, onOpenSession }) => {
  const subjects = catalog?.subjects || [];
  const inProgressExams = (dashboardData?.history || []).filter(
    (s: any) => s.status === 'in_progress'
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">
            Timed Mock Examination Center
          </h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Answers and explanations are withheld on the server during active exams and revealed upon final submission.
          </p>
        </div>
        <button
          type="button"
          onClick={() =>
            onStartSession({
              mode: 'exam',
              title: 'Comprehensive Multi-Subject Medical Mock Exam',
              requestedCount: 10,
              shuffleQuestions: true,
              shuffleOptions: true,
              timeLimitMinutes: 20,
            })
          }
          className="px-4 py-2.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          Start 10-MCQ Comprehensive Mock Exam (20 Min)
        </button>
      </div>

      {/* Interrupted / In-Progress Sessions */}
      {inProgressExams.length > 0 && (
        <div className="bg-amber-50/70 rounded-xl border border-amber-200 p-5 space-y-3">
          <h2 className="text-sm font-bold text-amber-950">
            Interrupted or In-Progress Sessions ({inProgressExams.length})
          </h2>
          <p className="text-xs text-amber-900">
            Your progress is automatically saved on the server. You can resume where you left off at any time:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {inProgressExams.map((sess: any) => (
              <div
                key={sess.id}
                className="bg-white rounded-lg border border-amber-200 p-3.5 flex items-center justify-between gap-3 text-xs"
              >
                <div>
                  <p className="font-semibold text-slate-900">{sess.title}</p>
                  <p className="text-slate-500 font-mono-tabular">
                    {sess.totalQuestions} MCQs · Mode: {sess.mode.toUpperCase()}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => onOpenSession(sess.id)}
                  className="px-3 py-1.5 font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-md cursor-pointer"
                >
                  Resume Session
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Subject-Specific Mock Exam Blocks */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {subjects.map((s: any) => (
          <div
            key={s.id}
            className="bg-white rounded-xl border border-slate-200 p-6 flex flex-col justify-between space-y-4"
          >
            <div className="space-y-2">
              <div className="text-xs text-slate-500 font-mono-tabular">
                Subject Examination Block · {s.questionCount} Available MCQs
              </div>
              <h2 className="text-lg font-bold text-slate-900">
                {s.title} — Mock Examination
              </h2>
              <p className="text-xs text-slate-600 leading-relaxed">
                Timed examination drawing from all published lectures in {s.title}. Includes shuffled options and post-submission performance breakdown.
              </p>
            </div>

            <div className="pt-4 border-t border-slate-100 flex items-center justify-between">
              <span className="text-xs font-mono-tabular text-slate-500">
                Time Limit: {Math.max(10, s.questionCount * 2)} Minutes
              </span>
              <button
                type="button"
                onClick={() =>
                  onStartSession({
                    mode: 'exam',
                    subjectIds: [s.id],
                    title: `${s.title} — Timed Mock Exam`,
                    shuffleQuestions: true,
                    shuffleOptions: true,
                    timeLimitMinutes: Math.max(10, s.questionCount * 2),
                  })
                }
                className="px-4 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg transition-colors cursor-pointer"
              >
                Begin Timed Exam
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// 5. BOOKMARKS & ANSWERED QUESTION REVIEW VIEW
// ============================================================================
export const BookmarksView: React.FC<{
  bookmarksData: { bookmarks: any[]; answeredQuestions: any[] } | null;
  catalog: any;
  onRefresh: () => void;
}> = ({ bookmarksData, catalog, onRefresh }) => {
  const [subTab, setSubTab] = useState<'bookmarks' | 'review'>('bookmarks');
  const [subjectFilter, setSubjectFilter] = useState<number | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<
    'all' | 'correct' | 'incorrect' | 'unanswered'
  >('all');
  const [expandedQuestionId, setExpandedQuestionId] = useState<number | null>(null);

  const subjects = catalog?.subjects || [];
  const bookmarks = bookmarksData?.bookmarks || [];
  const answered = bookmarksData?.answeredQuestions || [];

  const filteredBookmarks = bookmarks.filter((b: any) =>
    subjectFilter === 'all' ? true : b.subjectId === subjectFilter
  );

  const filteredAnswered = answered.filter((a: any) => {
    const subjMatch = subjectFilter === 'all' || a.subjectId === subjectFilter;
    const statusMatch = statusFilter === 'all' || a.status === statusFilter;
    return subjMatch && statusMatch;
  });

  const handleRemoveBookmark = async (questionId: number) => {
    await api.toggleBookmark(questionId);
    onRefresh();
  };

  const activeList = subTab === 'bookmarks' ? filteredBookmarks : filteredAnswered;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">
            Saved Bookmarks &amp; Question Review
          </h1>
          <p className="text-sm text-slate-600 mt-0.5">
            Review your private bookmarked questions or filter previously answered questions by Correct, Incorrect, or Unanswered status.
          </p>
        </div>

        {/* Mode Switcher */}
        <div className="flex items-center gap-1 p-1 bg-slate-200/70 rounded-lg">
          <button
            type="button"
            onClick={() => setSubTab('bookmarks')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
              subTab === 'bookmarks'
                ? 'bg-white text-slate-900 shadow-xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Bookmarked Questions ({bookmarks.length})
          </button>
          <button
            type="button"
            onClick={() => setSubTab('review')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
              subTab === 'review'
                ? 'bg-white text-slate-900 shadow-xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Previously Answered ({answered.length})
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-semibold text-slate-700">Subject Filter:</span>
          <select
            aria-label="Filter by Subject"
            value={subjectFilter}
            onChange={(e) =>
              setSubjectFilter(
                e.target.value === 'all' ? 'all' : Number(e.target.value)
              )
            }
            className="px-3 py-1.5 rounded-lg border border-slate-300 bg-white text-slate-800"
          >
            <option value="all">All Subjects</option>
            {subjects.map((s: any) => (
              <option key={s.id} value={s.id}>
                {s.title}
              </option>
            ))}
          </select>
        </div>

        {subTab === 'review' && (
          <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
            {(['all', 'correct', 'incorrect', 'unanswered'] as const).map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setStatusFilter(st)}
                className={`px-3 py-1 rounded-md font-medium capitalize cursor-pointer ${
                  statusFilter === st
                    ? 'bg-white text-slate-900 shadow-xs font-semibold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        )}
      </div>

      {activeList.length === 0 ? (
        <div className="bg-white rounded-xl border border-slate-200 p-8 text-center text-sm text-slate-600">
          {subTab === 'bookmarks'
            ? 'No bookmarked questions match the selected filter. Click "Bookmark" during any Study or Exam session to save questions here.'
            : 'No previously answered questions match the selected filter.'}
        </div>
      ) : (
        <div className="space-y-4">
          {activeList.map((item: any) => {
            const isOpen = expandedQuestionId === item.questionId;
            return (
              <div
                key={item.questionId}
                className="bg-white rounded-xl border border-slate-200 p-5 space-y-4"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
                  <div>
                    <span className="font-semibold text-slate-800">
                      {item.subjectTitle}
                    </span>{' '}
                    · {item.lectureTitle} · Difficulty: {item.difficulty}
                  </div>
                  <div className="flex items-center gap-3">
                    {item.status && (
                      <span
                        className={`font-semibold ${
                          item.status === 'correct'
                            ? 'text-emerald-700'
                            : item.status === 'incorrect'
                            ? 'text-red-700'
                            : 'text-amber-700'
                        }`}
                      >
                        Last Attempt: {item.status.toUpperCase()}
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => handleRemoveBookmark(item.questionId)}
                      className="text-slate-600 hover:text-red-700 font-medium cursor-pointer"
                    >
                      {subTab === 'bookmarks' || item.isBookmarked
                        ? 'Remove Bookmark'
                        : 'Add Bookmark'}
                    </button>
                  </div>
                </div>

                <p className="text-sm sm:text-base font-serif-academic text-slate-900 leading-relaxed">
                  {item.questionText}
                </p>

                {item.note && (
                  <p className="text-xs text-slate-600 italic bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                    Personal Note: {item.note}
                  </p>
                )}

                <div className="flex items-center justify-between pt-2">
                  <button
                    type="button"
                    onClick={() =>
                      setExpandedQuestionId(isOpen ? null : item.questionId)
                    }
                    className="text-xs font-semibold text-[#0284C7] hover:text-[#0369A1] cursor-pointer"
                  >
                    {isOpen
                      ? 'Hide Options & Explanation'
                      : 'View Options, Correct Answer & Explanation →'}
                  </button>
                </div>

                {isOpen && (
                  <div className="pt-4 border-t border-slate-100 space-y-3 text-xs">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {(['A', 'B', 'C', 'D'] as const).map((optKey) => {
                        const text = item[`option${optKey}`];
                        const isCorrect = item.correctAnswer === optKey;
                        return (
                          <div
                            key={optKey}
                            className={`p-3 rounded-lg border ${
                              isCorrect
                                ? 'border-emerald-500 bg-emerald-50/70 text-emerald-950 font-semibold'
                                : 'border-slate-200 text-slate-700'
                            }`}
                          >
                            <span className="font-mono-tabular font-bold mr-1.5">
                              {optKey}.
                            </span>
                            {text}
                            {isCorrect && (
                              <span className="ml-2 text-emerald-700">✓ Correct</span>
                            )}
                          </div>
                        );
                      })}
                    </div>

                    <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
                      <p className="font-bold text-slate-900">
                        Explanation (Correct Answer: {item.correctAnswer}):
                      </p>
                      <p className="text-slate-700 leading-relaxed">
                        {item.explanation}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 6. MY PROGRESS & ATTEMPT HISTORY VIEW
// ============================================================================
export const ProgressHistoryView: React.FC<{
  dashboardData: any;
  onOpenSession: (sessionId: number) => void;
}> = ({ dashboardData, onOpenSession }) => {
  const history = dashboardData?.history || [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">
          Complete Attempt History &amp; Longitudinal Progress
        </h1>
        <p className="text-sm text-slate-600 mt-0.5">
          Every completed Study, Custom, and Exam session is preserved with its exact historical question snapshot.
        </p>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        {history.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-600">
            You have not started any practice or examination sessions yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                  <th className="py-3 px-4 font-semibold">Date &amp; Time</th>
                  <th className="py-3 px-4 font-semibold">Session &amp; Lecture</th>
                  <th className="py-3 px-4 font-semibold">Mode</th>
                  <th className="py-3 px-4 font-semibold text-right">Questions</th>
                  <th className="py-3 px-4 font-semibold text-right">Score</th>
                  <th className="py-3 px-4 font-semibold text-right">Time Taken</th>
                  <th className="py-3 px-4 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {history.map((sess: any) => (
                  <tr key={sess.id} className="hover:bg-slate-50/70 text-slate-700">
                    <td className="py-3 px-4 font-mono-tabular whitespace-nowrap">
                      {new Date(sess.startedAt).toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      <p className="font-semibold text-slate-900">{sess.title}</p>
                      <p className="text-slate-500">
                        {sess.subjectTitle} · {sess.lectureTitle}
                      </p>
                    </td>
                    <td className="py-3 px-4 uppercase font-mono-tabular">
                      {sess.mode}
                    </td>
                    <td className="py-3 px-4 text-right font-mono-tabular">
                      {sess.totalQuestions}
                    </td>
                    <td className="py-3 px-4 text-right font-mono-tabular font-bold text-slate-900">
                      {sess.status === 'completed'
                        ? `${sess.scorePercentage}% (${sess.correctCount}/${sess.totalQuestions})`
                        : 'In Progress'}
                    </td>
                    <td className="py-3 px-4 text-right font-mono-tabular">
                      {Math.floor((sess.elapsedSeconds || 0) / 60)}m{' '}
                      {(sess.elapsedSeconds || 0) % 60}s
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        onClick={() => onOpenSession(sess.id)}
                        className="px-3 py-1.5 font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-md cursor-pointer"
                      >
                        {sess.status === 'completed'
                          ? 'Review Answers'
                          : 'Resume'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// 7. PROFILE, SETTINGS & ENTITLEMENT STATUS VIEW
// ============================================================================
export const ProfileSettingsView: React.FC<{
  user: UserProfile;
  onUserUpdated: (user: UserProfile) => void;
  onAccountDeleted: () => void;
}> = ({ user, onUserUpdated, onAccountDeleted }) => {
  const [displayName, setDisplayName] = useState(user.displayName);
  const [saving, setSaving] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [savingPassword, setSavingPassword] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false);

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setStatusMsg(null);
    setErrorMsg(null);
    try {
      const res = await api.updateProfile(displayName);
      onUserUpdated(res.user);
      setStatusMsg('Profile display name updated successfully.');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to update profile.');
    } finally {
      setSaving(false);
    }
  };

  const handlePasswordUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingPassword(true);
    setStatusMsg(null);
    setErrorMsg(null);
    try {
      if (user.hasPassword !== false) {
        const res = await api.changePassword(currentPassword, newPassword);
        onUserUpdated(res.user);
        setStatusMsg(res.message || 'Password updated and older sessions revoked.');
      } else {
        const res = await api.linkPassword(newPassword);
        onUserUpdated(res.user);
        setStatusMsg(res.message || 'Local password linked to your account.');
      }
      setCurrentPassword('');
      setNewPassword('');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to update password.');
    } finally {
      setSavingPassword(false);
    }
  };

  const handleConfirmDelete = async () => {
    try {
      await api.deleteAccount();
      onAccountDeleted();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to delete account.');
    }
  };

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">
          Student Profile &amp; Account Settings
        </h1>
        <p className="text-sm text-slate-600 mt-0.5">
          Manage your display name, inspect your account security metadata, and review your trial access entitlements.
        </p>
      </div>

      {statusMsg && (
        <div
          role="status"
          className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-800"
        >
          {statusMsg}
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

      {/* Profile Form */}
      <form
        onSubmit={handleSaveProfile}
        className="bg-white rounded-xl border border-slate-200 p-6 space-y-4"
      >
        <h2 className="text-base font-bold text-slate-900">Account Identity</h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div>
            <label
              htmlFor="profile-display-name"
              className="block font-semibold text-slate-700 mb-1"
            >
              Editable Display Name
            </label>
            <input
              id="profile-display-name"
              type="text"
              required
              minLength={2}
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0284C7]"
            />
          </div>

          <div>
            <label className="block font-semibold text-slate-700 mb-1">
              Registered Email Address
            </label>
            <input
              type="text"
              disabled
              value={user.email}
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-200 bg-slate-50 text-slate-500"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 text-xs text-slate-600 font-mono-tabular">
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <p className="font-sans text-slate-500">Authenticated User ID</p>
            <p className="font-semibold text-slate-900 truncate mt-0.5">{user.uid}</p>
          </div>
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <p className="font-sans text-slate-500">Account Role</p>
            <p className="font-semibold text-slate-900 uppercase mt-0.5">
              {user.role}
            </p>
          </div>
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <p className="font-sans text-slate-500">Account Created</p>
            <p className="font-semibold text-slate-900 mt-0.5">
              {new Date(user.createdAt).toLocaleDateString()}
            </p>
          </div>
        </div>

        <div className="pt-2 flex justify-end">
          <button
            type="submit"
            disabled={saving}
            className="px-5 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg cursor-pointer"
          >
            {saving ? 'Saving...' : 'Save Display Name'}
          </button>
        </div>
      </form>

      {/* Authenticated Password Change / Provider Account Password Linking */}
      <form
        onSubmit={handlePasswordUpdate}
        className="bg-white rounded-xl border border-slate-200 p-6 space-y-4"
      >
        <div>
          <h2 className="text-base font-bold text-slate-900">
            {user.hasPassword !== false
              ? 'Change Account Password'
              : 'Link Local Password to Account'}
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            {user.hasPassword !== false
              ? 'Updating your password automatically increments your session version and revokes any older active sessions.'
              : 'Attach a local password to your verified provider account so you can sign in with either Google or Email & Password.'}
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          {user.hasPassword !== false && (
            <div>
              <label
                htmlFor="profile-current-password"
                className="block font-semibold text-slate-700 mb-1"
              >
                Current Password
              </label>
              <input
                id="profile-current-password"
                type="password"
                required
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0284C7]"
              />
            </div>
          )}

          <div>
            <label
              htmlFor="profile-new-password"
              className="block font-semibold text-slate-700 mb-1"
            >
              New Password (min 8 characters)
            </label>
            <input
              id="profile-new-password"
              type="password"
              required
              minLength={8}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0284C7]"
            />
          </div>
        </div>

        <div className="pt-2 flex justify-end">
          <button
            type="submit"
            disabled={savingPassword}
            className="px-5 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg cursor-pointer"
          >
            {savingPassword
              ? 'Updating...'
              : user.hasPassword !== false
              ? 'Update Password'
              : 'Link Password'}
          </button>
        </div>
      </form>

      {/* Entitlement & Future Premium Architecture Status */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-slate-900">
            Academic Access Entitlement
          </h2>
          <span className="text-xs font-mono-tabular font-semibold text-emerald-700">
            Plan: {user.subscriptionTier.toUpperCase()} ({user.subscriptionStatus})
          </span>
        </div>
        <p className="text-xs text-slate-600 leading-relaxed">
          MedAtlas MCQ is currently operating in its open <strong>Free Trial Period</strong>. Every registered student has full access to all published subjects, lectures, practice sets, and mock examinations with no payment processing or locked questions.
        </p>
      </div>

      {/* Account Deletion & Privacy */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 space-y-3">
        <h2 className="text-base font-bold text-red-700">
          Privacy &amp; Permanent Account Deletion
        </h2>
        <p className="text-xs text-slate-600 leading-relaxed">
          Deleting your account permanently removes your profile, all saved exam sessions, question attempts, and bookmarks from the PostgreSQL database.
        </p>
        {!confirmDeleteOpen ? (
          <button
            type="button"
            onClick={() => setConfirmDeleteOpen(true)}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 rounded-lg cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Delete My Account &amp; Data
          </button>
        ) : (
          <div className="p-4 rounded-lg bg-red-50 border border-red-200 space-y-3">
            <p className="text-xs font-semibold text-red-900">
              Are you sure you want to permanently delete your account and all attempt history? This cannot be undone.
            </p>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={handleConfirmDelete}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-700 rounded-md cursor-pointer"
              >
                Yes, Permanently Delete
              </button>
              <button
                type="button"
                onClick={() => setConfirmDeleteOpen(false)}
                className="px-4 py-1.5 text-xs font-semibold text-slate-700 bg-white border border-slate-300 rounded-md cursor-pointer"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
