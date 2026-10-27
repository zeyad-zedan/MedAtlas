import React, { useState } from 'react';
import {
  Download,
  Eye,
  FileSpreadsheet,
  Plus,
  Search,
  ShieldCheck,
  Trash2,
  Upload,
  CheckCircle2,
  AlertTriangle,
  X,
} from 'lucide-react';
import { api } from '../lib/api.ts';
import { getSampleCsvTemplate } from '../lib/mcq-engine.ts';

interface AdminConsoleProps {
  adminData: any;
  loading: boolean;
  onRefresh: () => void;
}

type AdminSection = 'overview' | 'subjects' | 'lectures' | 'questions' | 'import';

export const AdminConsole: React.FC<AdminConsoleProps> = ({
  adminData,
  loading,
  onRefresh,
}) => {
  const [section, setSection] = useState<AdminSection>('overview');
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Subject form state
  const [editingSubject, setEditingSubject] = useState<any | null>(null);
  const [subjTitle, setSubjTitle] = useState('');
  const [subjDesc, setSubjDesc] = useState('');
  const [subjOrder, setSubjOrder] = useState(1);
  const [subjStatus, setSubjStatus] = useState<'published' | 'draft' | 'archived'>(
    'published'
  );

  // Lecture form state
  const [editingLecture, setEditingLecture] = useState<any | null>(null);
  const [lectSubjectId, setLectSubjectId] = useState<number>(0);
  const [lectTitle, setLectTitle] = useState('');
  const [lectDesc, setLectDesc] = useState('');
  const [lectNumber, setLectNumber] = useState(1);
  const [lectNotes, setLectNotes] = useState('');
  const [lectStatus, setLectStatus] = useState<'published' | 'draft' | 'archived'>(
    'published'
  );

  // Question form & filter state
  const [qSearch, setQSearch] = useState('');
  const [qSubjectFilter, setQSubjectFilter] = useState<number | 'all'>('all');
  const [qStatusFilter, setQStatusFilter] = useState<string>('all');
  const [editingQuestion, setEditingQuestion] = useState<any | null>(null);
  const [previewQuestion, setPreviewQuestion] = useState<any | null>(null);
  const [confirmDeleteQuestionId, setConfirmDeleteQuestionId] = useState<
    number | null
  >(null);

  const [qSubjectId, setQSubjectId] = useState<number>(0);
  const [qLectureId, setQLectureId] = useState<number>(0);
  const [qText, setQText] = useState('');
  const [qOptA, setQOptA] = useState('');
  const [qOptB, setQOptB] = useState('');
  const [qOptC, setQOptC] = useState('');
  const [qOptD, setQOptD] = useState('');
  const [qCorrect, setQCorrect] = useState<'A' | 'B' | 'C' | 'D'>('B');
  const [qExplanation, setQExplanation] = useState('');
  const [qExpA, setQExpA] = useState('');
  const [qExpB, setQExpB] = useState('');
  const [qExpC, setQExpC] = useState('');
  const [qExpD, setQExpD] = useState('');
  const [qDifficulty, setQDifficulty] = useState<'Easy' | 'Medium' | 'Hard'>(
    'Medium'
  );
  const [qTags, setQTags] = useState('');
  const [qStatus, setQStatus] = useState<'published' | 'draft' | 'archived'>(
    'published'
  );

  // CSV Bulk Import state
  const [csvFileName, setCsvFileName] = useState('sample_medical_import.csv');
  const [csvContent, setCsvContent] = useState('');
  const [csvPreviewReport, setCsvPreviewReport] = useState<any | null>(null);
  const [csvImportResult, setCsvImportResult] = useState<any | null>(null);
  const [validatingCsv, setValidatingCsv] = useState(false);
  const [importingCsv, setImportingCsv] = useState(false);

  if (loading || !adminData) {
    return (
      <div className="p-8 bg-white rounded-xl border border-slate-200 animate-pulse space-y-4">
        <div className="h-6 w-64 bg-slate-200 rounded" />
        <div className="h-32 bg-slate-100 rounded" />
      </div>
    );
  }

  const {
    metrics,
    subjects = [],
    lectures = [],
    questions = [],
    recentActivity = [],
    recentImports = [],
    auditLogs = [],
  } = adminData;

  const clearAlerts = () => {
    setFeedbackMsg(null);
    setErrorMsg(null);
  };

  // Subject Handlers
  const startEditSubject = (subj?: any) => {
    clearAlerts();
    if (subj) {
      setEditingSubject(subj);
      setSubjTitle(subj.title);
      setSubjDesc(subj.description);
      setSubjOrder(subj.displayOrder);
      setSubjStatus(subj.status);
    } else {
      setEditingSubject({ id: undefined });
      setSubjTitle('');
      setSubjDesc('');
      setSubjOrder(subjects.length + 1);
      setSubjStatus('published');
    }
  };

  const handleSaveSubject = async (e: React.FormEvent) => {
    e.preventDefault();
    clearAlerts();
    try {
      await api.saveSubject({
        id: editingSubject?.id,
        title: subjTitle,
        description: subjDesc,
        displayOrder: subjOrder,
        status: subjStatus,
      });
      setEditingSubject(null);
      setFeedbackMsg('Subject saved successfully.');
      onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to save subject.');
    }
  };

  // Lecture Handlers
  const startEditLecture = (lect?: any) => {
    clearAlerts();
    const defaultSubjId = subjects[0]?.id || 0;
    if (lect) {
      setEditingLecture(lect);
      setLectSubjectId(lect.subjectId);
      setLectTitle(lect.title);
      setLectDesc(lect.description);
      setLectNumber(lect.lectureNumber);
      setLectNotes(lect.educationalNotes || '');
      setLectStatus(lect.status);
    } else {
      setEditingLecture({ id: undefined });
      setLectSubjectId(defaultSubjId);
      setLectTitle('');
      setLectDesc('');
      setLectNumber(lectures.length + 1);
      setLectNotes('');
      setLectStatus('published');
    }
  };

  const handleSaveLecture = async (e: React.FormEvent) => {
    e.preventDefault();
    clearAlerts();
    try {
      await api.saveLecture({
        id: editingLecture?.id,
        subjectId: lectSubjectId,
        title: lectTitle,
        description: lectDesc,
        lectureNumber: lectNumber,
        educationalNotes: lectNotes,
        status: lectStatus,
      });
      setEditingLecture(null);
      setFeedbackMsg('Lecture saved successfully.');
      onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to save lecture.');
    }
  };

  // Question Handlers
  const startEditQuestion = (q?: any) => {
    clearAlerts();
    const defaultSubj = subjects[0]?.id || 0;
    const defaultLect =
      lectures.find((l: any) => l.subjectId === defaultSubj)?.id ||
      lectures[0]?.id ||
      0;

    if (q) {
      setEditingQuestion(q);
      setQSubjectId(q.subjectId);
      setQLectureId(q.lectureId);
      setQText(q.questionText);
      setQOptA(q.optionA);
      setQOptB(q.optionB);
      setQOptC(q.optionC);
      setQOptD(q.optionD);
      setQCorrect(q.correctAnswer);
      setQExplanation(q.explanation);
      setQExpA(q.explanationA || '');
      setQExpB(q.explanationB || '');
      setQExpC(q.explanationC || '');
      setQExpD(q.explanationD || '');
      setQDifficulty(q.difficulty);
      setQTags(q.tags || '');
      setQStatus(q.status);
    } else {
      setEditingQuestion({ id: undefined });
      setQSubjectId(defaultSubj);
      setQLectureId(defaultLect);
      setQText('');
      setQOptA('');
      setQOptB('');
      setQOptC('');
      setQOptD('');
      setQCorrect('B');
      setQExplanation('');
      setQExpA('');
      setQExpB('');
      setQExpC('');
      setQExpD('');
      setQDifficulty('Medium');
      setQTags('');
      setQStatus('published');
    }
  };

  const handleSaveQuestion = async (e: React.FormEvent) => {
    e.preventDefault();
    clearAlerts();
    try {
      await api.saveQuestion({
        id: editingQuestion?.id,
        subjectId: qSubjectId,
        lectureId: qLectureId,
        questionText: qText,
        optionA: qOptA,
        optionB: qOptB,
        optionC: qOptC,
        optionD: qOptD,
        correctAnswer: qCorrect,
        explanation: qExplanation,
        explanationA: qExpA,
        explanationB: qExpB,
        explanationC: qExpC,
        explanationD: qExpD,
        difficulty: qDifficulty,
        tags: qTags,
        status: qStatus,
      });
      setEditingQuestion(null);
      setFeedbackMsg(
        editingQuestion?.id
          ? 'Question updated with new version (historical student attempts preserved).'
          : 'New question added to the question bank.'
      );
      onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to save question.');
    }
  };

  const handleDeleteOrArchiveQuestion = async (questionId: number) => {
    clearAlerts();
    try {
      const res = await api.deleteOrArchiveQuestion(questionId);
      setConfirmDeleteQuestionId(null);
      setFeedbackMsg(res.message);
      onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to delete question.');
    }
  };

  // CSV Import & Export Handlers
  const handleDownloadSampleTemplate = () => {
    const csv = getSampleCsvTemplate();
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'medatlas_mcq_template.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportFullQuestionBank = async () => {
    clearAlerts();
    try {
      const csv = await api.exportQuestionBankCsv();
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'medatlas_question_bank_backup.csv';
      a.click();
      URL.revokeObjectURL(url);
      setFeedbackMsg('Exported full question bank backup CSV.');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to export question bank.');
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    clearAlerts();
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.csv')) {
      setErrorMsg('Invalid file format. Please upload a .csv file.');
      return;
    }
    if (file.size > 4 * 1024 * 1024) {
      setErrorMsg('File exceeds the 4 MB size limit.');
      return;
    }
    setCsvFileName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = String(ev.target?.result || '');
      setCsvContent(text);
      setCsvPreviewReport(null);
      setCsvImportResult(null);
    };
    reader.readAsText(file);
  };

  const handleLoadSampleIntoEditor = () => {
    clearAlerts();
    setCsvFileName('sample_batch_import.csv');
    setCsvContent(getSampleCsvTemplate());
    setCsvPreviewReport(null);
    setCsvImportResult(null);
  };

  const handleValidateCsv = async () => {
    clearAlerts();
    if (!csvContent.trim()) {
      setErrorMsg('Please upload a CSV file or load the sample CSV template first.');
      return;
    }
    setValidatingCsv(true);
    try {
      const report = await api.previewCsvImport(csvContent);
      setCsvPreviewReport(report);
    } catch (err: any) {
      setErrorMsg(err.message || 'CSV validation failed.');
    } finally {
      setValidatingCsv(false);
    }
  };

  const handleConfirmCsvImport = async () => {
    clearAlerts();
    setImportingCsv(true);
    try {
      const res = await api.executeCsvImport(csvFileName, csvContent);
      setCsvImportResult(res);
      setFeedbackMsg(
        `Bulk import completed: ${res.batch.importedCount} imported, ${res.batch.skippedCount} duplicate(s) skipped, ${res.batch.failedCount} invalid row(s) rejected.`
      );
      onRefresh();
    } catch (err: any) {
      setErrorMsg(err.message || 'CSV import failed.');
    } finally {
      setImportingCsv(false);
    }
  };

  const filteredQuestions = questions.filter((q: any) => {
    const matchSubj =
      qSubjectFilter === 'all' || q.subjectId === qSubjectFilter;
    const matchStatus = qStatusFilter === 'all' || q.status === qStatusFilter;
    const matchText =
      !qSearch.trim() ||
      q.questionText.toLowerCase().includes(qSearch.toLowerCase()) ||
      q.tags.toLowerCase().includes(qSearch.toLowerCase());
    return matchSubj && matchStatus && matchText;
  });

  return (
    <div className="space-y-6">
      {/* Admin Top Header & Navigation Tabs */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs font-semibold text-[#0284C7]">
              <ShieldCheck className="w-4 h-4" />
              <span>Verified Administrator Console · Server-Enforced RBAC</span>
            </div>
            <h1 className="text-2xl font-bold text-slate-900">
              Curriculum &amp; Question Bank Administration
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-1.5 p-1 bg-slate-100 rounded-lg overflow-x-auto">
          {(
            [
              { id: 'overview', label: 'Overview & Logs' },
              { id: 'subjects', label: `Subjects (${subjects.length})` },
              { id: 'lectures', label: `Lectures (${lectures.length})` },
              { id: 'questions', label: `Question Bank (${questions.length})` },
              { id: 'import', label: 'Bulk CSV Import & Export' },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => {
                setSection(tab.id);
                clearAlerts();
              }}
              className={`px-4 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                section === tab.id
                  ? 'bg-white text-slate-900 shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {feedbackMsg && (
        <div
          role="status"
          className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-800"
        >
          {feedbackMsg}
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

      {/* ====================================================================
          SECTION 1: ADMIN OVERVIEW & AUDIT LOGS
      ==================================================================== */}
      {section === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 font-mono-tabular">
            <div className="bg-white rounded-xl border border-slate-200 p-5">
              <p className="text-xs font-sans text-slate-500">Registered Users</p>
              <p className="text-2xl font-bold text-slate-900 mt-1">
                {metrics.totalUsers}
              </p>
            </div>
            <div className="bg-white rounded-xl border border-slate-200 p-5">
              <p className="text-xs font-sans text-slate-500">Published Subjects</p>
              <p className="text-2xl font-bold text-slate-900 mt-1">
                {metrics.publishedSubjects} / {metrics.totalSubjects}
              </p>
            </div>
            <div className="bg-white rounded-xl border border-slate-200 p-5">
              <p className="text-xs font-sans text-slate-500">Published Lectures</p>
              <p className="text-2xl font-bold text-slate-900 mt-1">
                {metrics.publishedLectures} / {metrics.totalLectures}
              </p>
            </div>
            <div className="bg-white rounded-xl border border-slate-200 p-5">
              <p className="text-xs font-sans text-slate-500">Published Questions</p>
              <p className="text-2xl font-bold text-[#0284C7] mt-1">
                {metrics.publishedQuestions} / {metrics.totalQuestions}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-6 bg-white rounded-xl border border-slate-200 p-6 space-y-4">
              <h2 className="text-base font-bold text-slate-900">
                Recent Student Sessions
              </h2>
              {recentActivity.length === 0 ? (
                <p className="text-xs text-slate-500">No recent sessions recorded.</p>
              ) : (
                <div className="space-y-2.5 text-xs">
                  {recentActivity.slice(0, 6).map((act: any) => (
                    <div
                      key={act.id}
                      className="p-3 rounded-lg border border-slate-200 flex items-center justify-between"
                    >
                      <div>
                        <p className="font-semibold text-slate-900">{act.title}</p>
                        <p className="text-slate-500 font-mono-tabular">
                          UID: {act.userUid} · Mode: {act.mode}
                        </p>
                      </div>
                      <span className="font-mono-tabular font-bold text-slate-800">
                        {act.status === 'completed'
                          ? `${act.scorePercentage}%`
                          : 'Active'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="lg:col-span-6 bg-white rounded-xl border border-slate-200 p-6 space-y-4">
              <h2 className="text-base font-bold text-slate-900">
                Administrative Audit Logs
              </h2>
              {auditLogs.length === 0 ? (
                <p className="text-xs text-slate-500">No audit entries yet.</p>
              ) : (
                <div className="space-y-2.5 text-xs max-h-72 overflow-y-auto">
                  {auditLogs.map((log: any) => (
                    <div
                      key={log.id}
                      className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1"
                    >
                      <div className="flex items-center justify-between font-mono-tabular text-[11px] text-slate-500">
                        <span className="font-semibold text-slate-800">
                          {log.action}
                        </span>
                        <span>{new Date(log.createdAt).toLocaleString()}</span>
                      </div>
                      <p className="text-slate-700">{log.details}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ====================================================================
          SECTION 2: SUBJECT MANAGEMENT
      ==================================================================== */}
      {section === 'subjects' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-slate-900">Manage Subjects</h2>
            <button
              type="button"
              onClick={() => startEditSubject()}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              New Subject
            </button>
          </div>

          {editingSubject && (
            <form
              onSubmit={handleSaveSubject}
              className="bg-white rounded-xl border border-slate-200 p-6 space-y-4"
            >
              <h3 className="text-sm font-bold text-slate-900">
                {editingSubject.id ? 'Edit Subject' : 'Create New Subject'}
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                <div className="sm:col-span-2">
                  <label className="block font-semibold text-slate-700 mb-1">
                    Subject Title
                  </label>
                  <input
                    type="text"
                    required
                    value={subjTitle}
                    onChange={(e) => setSubjTitle(e.target.value)}
                    placeholder="e.g., Neuroanatomy & Clinical Neuroscience"
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                  />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block font-semibold text-slate-700 mb-1">
                      Order
                    </label>
                    <input
                      type="number"
                      value={subjOrder}
                      onChange={(e) => setSubjOrder(Number(e.target.value))}
                      className="w-full px-3 py-2 text-sm font-mono-tabular rounded-lg border border-slate-300"
                    />
                  </div>
                  <div>
                    <label className="block font-semibold text-slate-700 mb-1">
                      Status
                    </label>
                    <select
                      value={subjStatus}
                      onChange={(e) => setSubjStatus(e.target.value as any)}
                      className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 bg-white"
                    >
                      <option value="published">Published</option>
                      <option value="draft">Draft</option>
                      <option value="archived">Archived</option>
                    </select>
                  </div>
                </div>
              </div>
              <div className="text-xs">
                <label className="block font-semibold text-slate-700 mb-1">
                  Description
                </label>
                <textarea
                  rows={2}
                  required
                  value={subjDesc}
                  onChange={(e) => setSubjDesc(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                />
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setEditingSubject(null)}
                  className="px-4 py-2 text-xs font-semibold text-slate-700 bg-slate-100 rounded-lg cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-semibold text-white bg-[#0284C7] rounded-lg cursor-pointer"
                >
                  Save Subject
                </button>
              </div>
            </form>
          )}

          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                  <th className="py-3 px-4 font-semibold">Order</th>
                  <th className="py-3 px-4 font-semibold">Subject Title</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  <th className="py-3 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {subjects.map((s: any) => (
                  <tr key={s.id} className="hover:bg-slate-50">
                    <td className="py-3 px-4 font-mono-tabular">{s.displayOrder}</td>
                    <td className="py-3 px-4">
                      <p className="font-bold text-slate-900">{s.title}</p>
                      <p className="text-slate-500">{s.description}</p>
                    </td>
                    <td className="py-3 px-4 uppercase font-mono-tabular font-semibold">
                      {s.status}
                    </td>
                    <td className="py-3 px-4 text-right space-x-3 whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => startEditSubject(s)}
                        className="font-semibold text-[#0284C7] hover:underline cursor-pointer"
                      >
                        Edit
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ====================================================================
          SECTION 3: LECTURE MANAGEMENT
      ==================================================================== */}
      {section === 'lectures' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-slate-900">Manage Lectures</h2>
            <button
              type="button"
              onClick={() => startEditLecture()}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              New Lecture
            </button>
          </div>

          {editingLecture && (
            <form
              onSubmit={handleSaveLecture}
              className="bg-white rounded-xl border border-slate-200 p-6 space-y-4 text-xs"
            >
              <h3 className="text-sm font-bold text-slate-900">
                {editingLecture.id ? 'Edit Lecture' : 'Create New Lecture'}
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Parent Subject
                  </label>
                  <select
                    value={lectSubjectId}
                    onChange={(e) => setLectSubjectId(Number(e.target.value))}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 bg-white"
                  >
                    {subjects.map((s: any) => (
                      <option key={s.id} value={s.id}>
                        {s.title}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Lecture Number
                  </label>
                  <input
                    type="number"
                    value={lectNumber}
                    onChange={(e) => setLectNumber(Number(e.target.value))}
                    className="w-full px-3 py-2 text-sm font-mono-tabular rounded-lg border border-slate-300"
                  />
                </div>
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Publication Status
                  </label>
                  <select
                    value={lectStatus}
                    onChange={(e) => setLectStatus(e.target.value as any)}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 bg-white"
                  >
                    <option value="published">Published</option>
                    <option value="draft">Draft</option>
                    <option value="archived">Archived</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">
                  Lecture Title
                </label>
                <input
                  type="text"
                  required
                  value={lectTitle}
                  onChange={(e) => setLectTitle(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">
                  Description
                </label>
                <textarea
                  rows={2}
                  required
                  value={lectDesc}
                  onChange={(e) => setLectDesc(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">
                  Educational Notes / High-Yield Summary (Optional)
                </label>
                <textarea
                  rows={4}
                  value={lectNotes}
                  onChange={(e) => setLectNotes(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                />
              </div>

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setEditingLecture(null)}
                  className="px-4 py-2 font-semibold text-slate-700 bg-slate-100 rounded-lg cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 font-semibold text-white bg-[#0284C7] rounded-lg cursor-pointer"
                >
                  Save Lecture
                </button>
              </div>
            </form>
          )}

          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                  <th className="py-3 px-4 font-semibold">Subject</th>
                  <th className="py-3 px-4 font-semibold">#</th>
                  <th className="py-3 px-4 font-semibold">Lecture Title</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  <th className="py-3 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {lectures.map((l: any) => (
                  <tr key={l.id} className="hover:bg-slate-50">
                    <td className="py-3 px-4 font-medium text-slate-700">
                      {l.subjectTitle}
                    </td>
                    <td className="py-3 px-4 font-mono-tabular">{l.lectureNumber}</td>
                    <td className="py-3 px-4">
                      <p className="font-bold text-slate-900">{l.title}</p>
                      <p className="text-slate-500">{l.description}</p>
                    </td>
                    <td className="py-3 px-4 uppercase font-mono-tabular font-semibold">
                      {l.status}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        onClick={() => startEditLecture(l)}
                        className="font-semibold text-[#0284C7] hover:underline cursor-pointer"
                      >
                        Edit
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ====================================================================
          SECTION 4: QUESTION BANK MANAGEMENT & STUDENT PREVIEW
      ==================================================================== */}
      {section === 'questions' && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={qSearch}
                  onChange={(e) => setQSearch(e.target.value)}
                  placeholder="Search question stem or tags..."
                  className="pl-9 pr-3 py-1.5 text-xs rounded-lg border border-slate-300 bg-white w-64"
                />
              </div>

              <select
                aria-label="Filter questions by subject"
                value={qSubjectFilter}
                onChange={(e) =>
                  setQSubjectFilter(
                    e.target.value === 'all' ? 'all' : Number(e.target.value)
                  )
                }
                className="px-3 py-1.5 text-xs rounded-lg border border-slate-300 bg-white"
              >
                <option value="all">All Subjects</option>
                {subjects.map((s: any) => (
                  <option key={s.id} value={s.id}>
                    {s.title}
                  </option>
                ))}
              </select>

              <select
                aria-label="Filter questions by status"
                value={qStatusFilter}
                onChange={(e) => setQStatusFilter(e.target.value)}
                className="px-3 py-1.5 text-xs rounded-lg border border-slate-300 bg-white"
              >
                <option value="all">All Statuses</option>
                <option value="published">Published</option>
                <option value="draft">Draft</option>
                <option value="archived">Archived</option>
              </select>
            </div>

            <button
              type="button"
              onClick={() => startEditQuestion()}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              Create Question Manually
            </button>
          </div>

          {editingQuestion && (
            <form
              onSubmit={handleSaveQuestion}
              className="bg-white rounded-xl border border-slate-200 p-6 space-y-4 text-xs"
            >
              <h3 className="text-sm font-bold text-slate-900">
                {editingQuestion.id
                  ? `Edit Question #${editingQuestion.id} (v${editingQuestion.version})`
                  : 'Create New Multiple-Choice Question'}
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Subject
                  </label>
                  <select
                    value={qSubjectId}
                    onChange={(e) => {
                      const nextSubj = Number(e.target.value);
                      setQSubjectId(nextSubj);
                      const firstLect = lectures.find(
                        (l: any) => l.subjectId === nextSubj
                      );
                      if (firstLect) setQLectureId(firstLect.id);
                    }}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 bg-white"
                  >
                    {subjects.map((s: any) => (
                      <option key={s.id} value={s.id}>
                        {s.title}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Lecture
                  </label>
                  <select
                    value={qLectureId}
                    onChange={(e) => setQLectureId(Number(e.target.value))}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 bg-white"
                  >
                    {lectures
                      .filter((l: any) => l.subjectId === qSubjectId)
                      .map((l: any) => (
                        <option key={l.id} value={l.id}>
                          {l.title}
                        </option>
                      ))}
                  </select>
                </div>

                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Difficulty
                  </label>
                  <select
                    value={qDifficulty}
                    onChange={(e) => setQDifficulty(e.target.value as any)}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 bg-white"
                  >
                    <option value="Easy">Easy</option>
                    <option value="Medium">Medium</option>
                    <option value="Hard">Hard</option>
                  </select>
                </div>

                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Status
                  </label>
                  <select
                    value={qStatus}
                    onChange={(e) => setQStatus(e.target.value as any)}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 bg-white"
                  >
                    <option value="published">Published</option>
                    <option value="draft">Draft</option>
                    <option value="archived">Archived</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">
                  Clinical Vignette / Question Stem
                </label>
                <textarea
                  rows={3}
                  required
                  value={qText}
                  onChange={(e) => setQText(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Option A
                  </label>
                  <input
                    type="text"
                    required
                    value={qOptA}
                    onChange={(e) => setQOptA(e.target.value)}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                  />
                </div>
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Option B
                  </label>
                  <input
                    type="text"
                    required
                    value={qOptB}
                    onChange={(e) => setQOptB(e.target.value)}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                  />
                </div>
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Option C
                  </label>
                  <input
                    type="text"
                    required
                    value={qOptC}
                    onChange={(e) => setQOptC(e.target.value)}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                  />
                </div>
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Option D
                  </label>
                  <input
                    type="text"
                    required
                    value={qOptD}
                    onChange={(e) => setQOptD(e.target.value)}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Correct Answer Key
                  </label>
                  <select
                    value={qCorrect}
                    onChange={(e) => setQCorrect(e.target.value as any)}
                    className="w-full px-3 py-2 text-sm font-mono-tabular font-bold rounded-lg border border-slate-300 bg-white"
                  >
                    <option value="A">Option A</option>
                    <option value="B">Option B</option>
                    <option value="C">Option C</option>
                    <option value="D">Option D</option>
                  </select>
                </div>
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Topic Tags (comma-separated)
                  </label>
                  <input
                    type="text"
                    value={qTags}
                    onChange={(e) => setQTags(e.target.value)}
                    placeholder="e.g., Collagen,Extracellular Matrix"
                    className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                  />
                </div>
              </div>

              <div>
                <label className="block font-semibold text-slate-700 mb-1">
                  Primary Explanation for Correct Answer
                </label>
                <textarea
                  rows={2}
                  required
                  value={qExplanation}
                  onChange={(e) => setQExplanation(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300"
                />
              </div>

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setEditingQuestion(null)}
                  className="px-4 py-2 font-semibold text-slate-700 bg-slate-100 rounded-lg cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 font-semibold text-white bg-[#0284C7] rounded-lg cursor-pointer"
                >
                  Save Question
                </button>
              </div>
            </form>
          )}

          <div className="space-y-3">
            {filteredQuestions.map((q: any) => (
              <div
                key={q.id}
                className="bg-white rounded-xl border border-slate-200 p-5 space-y-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
                  <div className="font-mono-tabular">
                    #{q.id} (v{q.version}) · {q.subjectTitle} · {q.lectureTitle} ·{' '}
                    Difficulty: {q.difficulty} · Status: {q.status.toUpperCase()}
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      type="button"
                      onClick={() => setPreviewQuestion(q)}
                      className="inline-flex items-center gap-1 font-semibold text-slate-700 hover:text-slate-900 cursor-pointer"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      Student Preview
                    </button>
                    <button
                      type="button"
                      onClick={() => startEditQuestion(q)}
                      className="font-semibold text-[#0284C7] hover:underline cursor-pointer"
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmDeleteQuestionId(q.id)}
                      className="font-semibold text-red-700 hover:underline cursor-pointer"
                    >
                      Delete / Archive
                    </button>
                  </div>
                </div>

                <p className="text-sm font-serif-academic text-slate-900">
                  {q.questionText}
                </p>

                <div className="text-xs text-slate-500 font-mono-tabular">
                  Correct Answer: Option {q.correctAnswer} ({q[`option${q.correctAnswer}`]})
                </div>

                {confirmDeleteQuestionId === q.id && (
                  <div className="p-3 rounded-lg bg-red-50 border border-red-200 flex items-center justify-between text-xs">
                    <span className="text-red-900 font-medium">
                      Confirm action on Question #{q.id}: If students have already attempted this question, it will be safely archived rather than destroyed.
                    </span>
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        onClick={() => handleDeleteOrArchiveQuestion(q.id)}
                        className="px-3 py-1 font-semibold text-white bg-red-600 rounded cursor-pointer"
                      >
                        Confirm
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmDeleteQuestionId(null)}
                        className="px-3 py-1 font-semibold text-slate-700 bg-white border border-slate-300 rounded cursor-pointer"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ====================================================================
          SECTION 5: BULK CSV QUESTION IMPORT & EXPORT
      ==================================================================== */}
      {section === 'import' && (
        <div className="space-y-6">
          <div className="bg-white rounded-xl border border-slate-200 p-6 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
              <div>
                <h2 className="text-lg font-bold text-slate-900">
                  Bulk CSV Question Bank Import &amp; Backup Export
                </h2>
                <p className="text-xs text-slate-600 mt-0.5">
                  Download the official 16-column CSV template, validate your rows before importing, or export the entire question bank as a backup.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={handleDownloadSampleTemplate}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  1. Download CSV Template
                </button>
                <button
                  type="button"
                  onClick={handleLoadSampleIntoEditor}
                  className="px-3.5 py-2 text-xs font-semibold text-[#0284C7] bg-sky-50 hover:bg-sky-100 rounded-lg cursor-pointer"
                >
                  Load Sample CSV Rows
                </button>
                <button
                  type="button"
                  onClick={handleExportFullQuestionBank}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg cursor-pointer"
                >
                  <FileSpreadsheet className="w-3.5 h-3.5" />
                  Export Full Question Bank CSV
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-5 space-y-3 text-xs">
                <label className="block font-bold text-slate-900">
                  2. Upload CSV File (.csv, max 4 MB)
                </label>
                <input
                  type="file"
                  accept=".csv,text/csv"
                  onChange={handleFileUpload}
                  className="block w-full text-xs text-slate-600 file:mr-3 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-[#0284C7] file:text-white hover:file:bg-[#0369A1] cursor-pointer"
                />
                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1 text-slate-600">
                  <p className="font-semibold text-slate-900">
                    Documented CSV Columns:
                  </p>
                  <p className="font-mono-tabular text-[11px] leading-relaxed">
                    subject, lecture, question_text, option_a, option_b, option_c, option_d, correct_answer, explanation, explanation_a, explanation_b, explanation_c, explanation_d, difficulty, tags, status
                  </p>
                </div>
              </div>

              <div className="lg:col-span-7 space-y-3 text-xs">
                <label
                  htmlFor="csv-textarea"
                  className="block font-bold text-slate-900"
                >
                  CSV Payload Inspector / Editor ({csvFileName})
                </label>
                <textarea
                  id="csv-textarea"
                  rows={6}
                  value={csvContent}
                  onChange={(e) => {
                    setCsvContent(e.target.value);
                    setCsvPreviewReport(null);
                  }}
                  placeholder="Paste CSV rows here or click 'Load Sample CSV Rows' above..."
                  className="w-full p-3 font-mono-tabular text-xs rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#0284C7]"
                />
                <div className="flex justify-end gap-3">
                  <button
                    type="button"
                    onClick={handleValidateCsv}
                    disabled={validatingCsv}
                    className="px-4 py-2 text-xs font-semibold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-lg cursor-pointer"
                  >
                    {validatingCsv
                      ? 'Validating...'
                      : '3. Validate & Preview Import'}
                  </button>
                </div>
              </div>
            </div>

            {/* Validation Preview Report */}
            {csvPreviewReport && (
              <div className="pt-5 border-t border-slate-200 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div className="space-y-0.5">
                    <h3 className="text-sm font-bold text-slate-900">
                      Validation Preview Report
                    </h3>
                    <p className="text-xs text-slate-600 font-mono-tabular">
                      Total Rows: {csvPreviewReport.totalRows} · Valid:{' '}
                      <span className="text-emerald-700 font-bold">
                        {csvPreviewReport.validCount}
                      </span>{' '}
                      · Duplicates:{' '}
                      <span className="text-amber-700 font-bold">
                        {csvPreviewReport.duplicateCount}
                      </span>{' '}
                      · Invalid:{' '}
                      <span className="text-red-700 font-bold">
                        {csvPreviewReport.invalidCount}
                      </span>
                    </p>
                  </div>

                  {csvPreviewReport.validCount > 0 && (
                    <button
                      type="button"
                      onClick={handleConfirmCsvImport}
                      disabled={importingCsv}
                      className="px-5 py-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg cursor-pointer"
                    >
                      {importingCsv
                        ? 'Importing...'
                        : `4. Confirm Import of ${csvPreviewReport.validCount} Valid Record(s)`}
                    </button>
                  )}
                </div>

                {csvPreviewReport.headerErrors?.length > 0 && (
                  <div className="p-3.5 rounded-lg bg-red-50 border border-red-200 text-xs text-red-800">
                    {csvPreviewReport.headerErrors.join(' ')}
                  </div>
                )}

                <div className="space-y-2 max-h-80 overflow-y-auto">
                  {(csvPreviewReport.rows || []).map((r: any) => (
                    <div
                      key={r.rowNumber}
                      className={`p-3 rounded-lg border text-xs ${
                        r.isValid
                          ? 'border-emerald-200 bg-emerald-50/40'
                          : r.isDuplicate
                          ? 'border-amber-200 bg-amber-50/40'
                          : 'border-red-200 bg-red-50/40'
                      }`}
                    >
                      <div className="flex items-center justify-between font-mono-tabular">
                        <span className="font-bold text-slate-900">
                          CSV Row #{r.rowNumber} · {r.subject || 'Missing Subject'} →{' '}
                          {r.lecture || 'Missing Lecture'}
                        </span>
                        <span
                          className={`font-semibold ${
                            r.isValid
                              ? 'text-emerald-700'
                              : r.isDuplicate
                              ? 'text-amber-700'
                              : 'text-red-700'
                          }`}
                        >
                          {r.isValid
                            ? '✓ Ready to Import'
                            : r.isDuplicate
                            ? 'Skipped (Duplicate)'
                            : '✕ Invalid Row'}
                        </span>
                      </div>
                      <p className="text-slate-700 truncate mt-1">
                        {r.questionText || '(Empty question stem)'}
                      </p>
                      {r.errors?.length > 0 && (
                        <ul className="mt-1.5 text-red-700 list-disc list-inside space-y-0.5">
                          {r.errors.map((err: string, i: number) => (
                            <li key={i}>{err}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Student Preview Modal */}
      {previewQuestion && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-xs p-4"
        >
          <div className="w-full max-w-2xl rounded-xl bg-white border border-slate-200 shadow-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <p className="text-xs text-slate-500">
                  Student Interface Preview · {previewQuestion.subjectTitle} ·{' '}
                  {previewQuestion.lectureTitle}
                </p>
                <h3 className="text-base font-bold text-slate-900">
                  Question #{previewQuestion.id} ({previewQuestion.difficulty})
                </h3>
              </div>
              <button
                type="button"
                aria-label="Close preview"
                onClick={() => setPreviewQuestion(null)}
                className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-base font-serif-academic text-slate-900 leading-relaxed">
              {previewQuestion.questionText}
            </p>

            <div className="space-y-2 text-xs">
              {(['A', 'B', 'C', 'D'] as const).map((opt) => {
                const isCorrect = previewQuestion.correctAnswer === opt;
                return (
                  <div
                    key={opt}
                    className={`p-3 rounded-lg border ${
                      isCorrect
                        ? 'border-emerald-500 bg-emerald-50 text-emerald-950 font-semibold'
                        : 'border-slate-200 text-slate-700'
                    }`}
                  >
                    <span className="font-mono-tabular font-bold mr-2">{opt}.</span>
                    {previewQuestion[`option${opt}`]}
                  </div>
                );
              })}
            </div>

            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-700 space-y-1">
              <p className="font-bold text-slate-900">Explanation:</p>
              <p>{previewQuestion.explanation}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
