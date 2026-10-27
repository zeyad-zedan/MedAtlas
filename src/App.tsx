/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  BookOpen,
  Bookmark,
  Clock,
  GraduationCap,
  History,
  LayoutDashboard,
  LogOut,
  Menu,
  ShieldCheck,
  SlidersHorizontal,
  User,
  X,
} from 'lucide-react';
import { api, subscribeToAuthChanges, type UserProfile } from './lib/api.ts';
import { PublicLanding } from './components/PublicLanding.tsx';
import { McqSessionPlayer } from './components/McqSessionPlayer.tsx';
import {
  DashboardView,
  SubjectsAndLecturesView,
  CustomPracticeView,
  MockExamsView,
  BookmarksView,
  ProgressHistoryView,
  ProfileSettingsView,
} from './components/StudentViews.tsx';
import { AdminConsole } from './components/AdminConsole.tsx';

export default function App() {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [initializingAuth, setInitializingAuth] = useState(true);
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [catalog, setCatalog] = useState<any | null>(null);
  const [loadingCatalog, setLoadingCatalog] = useState(true);

  const [dashboardData, setDashboardData] = useState<any | null>(null);
  const [loadingDashboard, setLoadingDashboard] = useState(false);

  const [bookmarksData, setBookmarksData] = useState<any | null>(null);
  const [adminData, setAdminData] = useState<any | null>(null);
  const [loadingAdmin, setLoadingAdmin] = useState(false);

  const [activeSession, setActiveSession] = useState<any | null>(null);
  const [sessionShortfall, setSessionShortfall] = useState<string | null>(null);
  const [globalError, setGlobalError] = useState<string | null>(null);

  const loadCatalog = useCallback(async () => {
    setLoadingCatalog(true);
    try {
      const data = await api.getCatalog();
      setCatalog(data);
    } catch (err: any) {
      console.error('Failed to load catalog:', err);
    } finally {
      setLoadingCatalog(false);
    }
  }, []);

  const loadStudentWorkspaceData = useCallback(async () => {
    setLoadingDashboard(true);
    try {
      const [dash, bkm] = await Promise.all([
        api.getDashboard(),
        api.getBookmarks(),
      ]);
      setDashboardData(dash);
      setBookmarksData(bkm);
    } catch (err: any) {
      console.error('Error loading workspace data:', err);
    } finally {
      setLoadingDashboard(false);
    }
  }, []);

  const loadAdminData = useCallback(async () => {
    setLoadingAdmin(true);
    try {
      const data = await api.getAdminOverview();
      setAdminData(data);
    } catch (err: any) {
      setGlobalError(err.message || 'Failed to load admin console.');
    } finally {
      setLoadingAdmin(false);
    }
  }, []);

  useEffect(() => {
    loadCatalog();
    const unsubscribe = subscribeToAuthChanges((resolvedUser) => {
      setUser(resolvedUser);
      setInitializingAuth(false);
    });
    return () => unsubscribe();
  }, [loadCatalog]);

  useEffect(() => {
    if (user) {
      loadCatalog();
      loadStudentWorkspaceData();
      if (user.role === 'admin') {
        loadAdminData();
      }
    }
  }, [user, loadCatalog, loadStudentWorkspaceData, loadAdminData]);

  const handleAuthenticated = (loggedInUser: UserProfile, initialTab?: string) => {
    setUser(loggedInUser);
    setActiveTab(initialTab || 'dashboard');
    setGlobalError(null);
  };

  const handleLogout = async () => {
    await api.logout();
    setUser(null);
    setActiveSession(null);
    setDashboardData(null);
    setBookmarksData(null);
    setAdminData(null);
    setActiveTab('dashboard');
  };

  const handleStartSession = async (params: any) => {
    setGlobalError(null);
    try {
      const res = await api.startSession(params);
      setActiveSession(res.session);
      setSessionShortfall(res.shortfallNotice);
    } catch (err: any) {
      setGlobalError(err.message || 'Could not start question session.');
    }
  };

  const handleOpenExistingSession = async (sessionId: number) => {
    setGlobalError(null);
    try {
      const res = await api.getSession(sessionId);
      setActiveSession(res.session);
      setSessionShortfall(null);
    } catch (err: any) {
      setGlobalError(err.message || 'Could not load session.');
    }
  };

  if (initializingAuth) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#F8FAFC] text-slate-600 text-sm">
        Loading MedAtlas MCQ...
      </div>
    );
  }

  if (!user) {
    return (
      <PublicLanding
        catalog={catalog}
        loadingCatalog={loadingCatalog}
        onAuthenticated={handleAuthenticated}
      />
    );
  }

  const navItems = [
    { id: 'dashboard', label: 'Home', icon: LayoutDashboard },
    { id: 'subjects', label: 'Subjects', icon: BookOpen },
    { id: 'lectures', label: 'Lectures', icon: GraduationCap },
    { id: 'practice', label: 'Practice MCQs', icon: SlidersHorizontal },
    { id: 'exams', label: 'Mock Exams', icon: Clock },
    { id: 'bookmarks', label: 'Bookmarks', icon: Bookmark },
    { id: 'progress', label: 'My Progress', icon: History },
    { id: 'profile', label: 'Profile & Settings', icon: User },
  ];

  if (user.role === 'admin') {
    navItems.push({ id: 'admin', label: 'Admin Console', icon: ShieldCheck });
  }

  return (
    <div className="min-h-screen flex bg-[#F8FAFC] text-[#0F172A]">
      {/* Desktop Left Sidebar Navigation (260px) */}
      <aside className="hidden lg:flex lg:w-64 lg:flex-col lg:fixed lg:inset-y-0 bg-white border-r border-slate-200 z-20">
        <div className="px-6 py-5 border-b border-slate-200 flex items-center justify-between">
          <span className="text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap">
            MedAtlas MCQ
          </span>
        </div>

        <nav
          aria-label="Student Workspace Navigation"
          className="flex-1 px-3 py-4 space-y-1 overflow-y-auto"
        >
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = !activeSession && activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  setActiveSession(null);
                  setActiveTab(item.id);
                  setGlobalError(null);
                }}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap cursor-pointer ${
                  isActive
                    ? 'bg-sky-50 text-[#0284C7] font-semibold'
                    : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-200 space-y-3 text-xs">
          <div className="px-2">
            <p className="font-bold text-slate-900 truncate">{user.displayName}</p>
            <p className="text-slate-500 truncate">{user.email}</p>
            <p className="text-[11px] font-mono-tabular text-slate-400 uppercase mt-0.5">
              {user.role === 'admin' ? 'Platform Administrator' : 'Medical Student'} · Free Trial
            </p>
          </div>

          <button
            type="button"
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 text-xs font-semibold text-slate-700 hover:text-red-700 bg-slate-100 hover:bg-red-50 rounded-lg transition-colors cursor-pointer"
          >
            <LogOut className="w-4 h-4" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 lg:pl-64 flex flex-col min-w-0">
        {/* Top Workspace Header (Strict 3-Zone Top Bar Contract) */}
        <header className="sticky top-0 z-10 bg-white/95 backdrop-blur border-b border-slate-200 px-6 py-3.5 flex items-center justify-between gap-8">
          <div className="flex items-center gap-3">
            <button
              type="button"
              aria-label="Toggle mobile navigation"
              onClick={() => setMobileMenuOpen((o) => !o)}
              className="lg:hidden p-1.5 text-slate-600 hover:text-slate-900 rounded-lg cursor-pointer"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
            <span className="text-sm font-semibold text-slate-700 whitespace-nowrap shrink-0">
              {activeSession
                ? `Active Session / ${activeSession.title}`
                : `Workspace / ${
                    navItems.find((n) => n.id === activeTab)?.label || 'Dashboard'
                  }`}
            </span>
          </div>

          <div className="hidden sm:flex items-center gap-6 text-xs text-slate-500 font-mono-tabular">
            <span>{user.displayName}</span>
            <span>·</span>
            <span>
              {user.role === 'admin' ? 'Administrator Access' : 'Access: Free Trial Unlocked'}
            </span>
          </div>

          <div className="flex items-center shrink-0">
            <button
              type="button"
              onClick={handleLogout}
              className="px-3.5 py-1.5 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Sign Out
            </button>
          </div>
        </header>

        {/* Mobile Navigation Drawer */}
        {mobileMenuOpen && (
          <div className="lg:hidden bg-white border-b border-slate-200 px-4 py-3 space-y-2">
            <div className="space-y-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveSession(null);
                      setActiveTab(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-medium rounded-lg cursor-pointer ${
                      activeTab === item.id
                        ? 'bg-sky-50 text-[#0284C7] font-semibold'
                        : 'text-slate-700'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
            <div className="pt-2 border-t border-slate-100 flex items-center justify-between gap-2">
              <span className="text-xs text-slate-500 truncate">{user.email}</span>
              <span className="text-[11px] font-mono-tabular text-slate-400 uppercase">
                {user.role === 'admin' ? 'Admin' : 'Student'}
              </span>
            </div>
          </div>
        )}

        {/* Workspace Viewport */}
        <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {globalError && (
            <div
              role="alert"
              className="mb-6 p-4 rounded-xl bg-red-50 border border-red-200 text-xs text-red-800 flex items-center justify-between"
            >
              <span>{globalError}</span>
              <button
                type="button"
                onClick={() => setGlobalError(null)}
                className="font-semibold underline ml-4 cursor-pointer"
              >
                Dismiss
              </button>
            </div>
          )}

          {activeSession ? (
            <McqSessionPlayer
              initialSession={activeSession}
              shortfallNotice={sessionShortfall}
              onExit={() => {
                setActiveSession(null);
                loadStudentWorkspaceData();
              }}
              onSessionCompleted={(completed) => {
                setActiveSession(completed);
                loadStudentWorkspaceData();
              }}
            />
          ) : (
            <>
              {activeTab === 'dashboard' && (
                <DashboardView
                  dashboardData={dashboardData}
                  loading={loadingDashboard}
                  onStartQuickSession={handleStartSession}
                  onOpenSession={handleOpenExistingSession}
                  onNavigateTab={setActiveTab}
                />
              )}

              {(activeTab === 'subjects' || activeTab === 'lectures') && (
                <SubjectsAndLecturesView
                  catalog={catalog}
                  onStartSession={handleStartSession}
                />
              )}

              {activeTab === 'practice' && (
                <CustomPracticeView
                  catalog={catalog}
                  onStartSession={handleStartSession}
                />
              )}

              {activeTab === 'exams' && (
                <MockExamsView
                  catalog={catalog}
                  dashboardData={dashboardData}
                  onStartSession={handleStartSession}
                  onOpenSession={handleOpenExistingSession}
                />
              )}

              {activeTab === 'bookmarks' && (
                <BookmarksView
                  bookmarksData={bookmarksData}
                  catalog={catalog}
                  onRefresh={loadStudentWorkspaceData}
                />
              )}

              {activeTab === 'progress' && (
                <ProgressHistoryView
                  dashboardData={dashboardData}
                  onOpenSession={handleOpenExistingSession}
                />
              )}

              {activeTab === 'profile' && (
                <ProfileSettingsView
                  user={user}
                  onUserUpdated={(updatedUser) => setUser(updatedUser)}
                  onAccountDeleted={handleLogout}
                />
              )}

              {activeTab === 'admin' && user.role === 'admin' && (
                <AdminConsole
                  adminData={adminData}
                  loading={loadingAdmin}
                  onRefresh={() => {
                    loadAdminData();
                    loadCatalog();
                  }}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
