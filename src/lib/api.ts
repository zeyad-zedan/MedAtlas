import {
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  sendPasswordResetEmail,
} from 'firebase/auth';
import { auth, googleAuthProvider } from './firebase.ts';

const STORAGE_TOKEN_KEY = 'medatlas_session_token';

let inMemoryAuthToken: string | null =
  typeof window !== 'undefined' ? window.localStorage.getItem(STORAGE_TOKEN_KEY) : null;

export function setAuthToken(token: string | null) {
  inMemoryAuthToken = token;
  if (typeof window !== 'undefined') {
    if (token) {
      window.localStorage.setItem(STORAGE_TOKEN_KEY, token);
    } else {
      window.localStorage.removeItem(STORAGE_TOKEN_KEY);
    }
  }
}

export function getAuthToken(): string | null {
  return inMemoryAuthToken;
}

export function subscribeToAuthChanges(
  onUserResolved: (user: UserProfile | null) => void
): () => void {
  const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
    try {
      if (firebaseUser) {
        const idToken = await firebaseUser.getIdToken();
        setAuthToken(idToken);
        const data = await api.getCurrentUser();
        onUserResolved(data.user);
      } else if (getAuthToken()) {
        const data = await api.getCurrentUser();
        onUserResolved(data.user);
      } else {
        onUserResolved(null);
      }
    } catch {
      setAuthToken(null);
      onUserResolved(null);
    }
  });
  return unsubscribe;
}

async function apiRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };

  if (inMemoryAuthToken) {
    headers['Authorization'] = `Bearer ${inMemoryAuthToken}`;
  }

  const res = await fetch(path, {
    ...options,
    headers,
  });

  if (!res.ok) {
    if (res.status === 401) {
      setAuthToken(null);
    }
    let errMsg = `Request failed (${res.status})`;
    try {
      const errBody = await res.json();
      if (errBody?.error) errMsg = errBody.error;
    } catch {
      // ignore json parse error
    }
    throw new Error(errMsg);
  }

  return res.json() as Promise<T>;
}

export interface UserProfile {
  id: number;
  uid: string;
  email: string;
  displayName: string;
  authProvider?: string;
  hasPassword?: boolean;
  role: 'student' | 'admin';
  subscriptionTier: string;
  subscriptionStatus: string;
  emailVerified: boolean;
  preferences: string;
  createdAt: string;
  updatedAt: string;
}

export const api = {
  // Public Catalog
  getCatalog: () =>
    apiRequest<{
      subjects: any[];
      lectures: any[];
      totalPublishedQuestions: number;
    }>('/api/catalog'),

  // Authentication
  registerWithEmail: async (email: string, password: string, displayName: string) => {
    const data = await apiRequest<{ token: string; user: UserProfile }>(
      '/api/auth/register',
      {
        method: 'POST',
        body: JSON.stringify({ email, password, displayName }),
      }
    );
    setAuthToken(data.token);
    return data.user;
  },

  loginWithEmail: async (email: string, password: string) => {
    const data = await apiRequest<{ token: string; user: UserProfile }>(
      '/api/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      }
    );
    setAuthToken(data.token);
    return data.user;
  },

  loginWithGooglePopup: async () => {
    const result = await signInWithPopup(auth, googleAuthProvider);
    const idToken = await result.user.getIdToken();
    setAuthToken(idToken);
    const data = await apiRequest<{ user: UserProfile }>('/api/auth/me');
    return data.user;
  },

  requestPasswordReset: async (email: string) => {
    const res = await apiRequest<{
      accepted: boolean;
      message: string;
      expiresInMinutes: number;
    }>('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
    // Also trigger Firebase Auth password reset email best-effort if the user is registered in Firebase
    try {
      await sendPasswordResetEmail(auth, email.trim());
    } catch {
      // Enumeration-safe: ignore Firebase error if account is local-only or non-existent
    }
    return res;
  },

  confirmPasswordReset: (token: string, newPassword: string) =>
    apiRequest<{ message: string }>('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, newPassword }),
    }),

  changePassword: async (currentPassword: string, newPassword: string) => {
    const data = await apiRequest<{
      message: string;
      token: string;
      user: UserProfile;
    }>('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    });
    setAuthToken(data.token);
    return data;
  },

  linkPassword: async (newPassword: string) => {
    const data = await apiRequest<{
      message: string;
      token: string;
      user: UserProfile;
    }>('/api/auth/link-password', {
      method: 'POST',
      body: JSON.stringify({ newPassword }),
    });
    setAuthToken(data.token);
    return data;
  },

  logout: async () => {
    if (inMemoryAuthToken) {
      try {
        await apiRequest<{ loggedOut: boolean }>('/api/auth/logout', {
          method: 'POST',
        });
      } catch {
        // ignore if token already expired
      }
    }
    setAuthToken(null);
    try {
      await signOut(auth);
    } catch {
      // ignore if not signed in via firebase
    }
  },

  getCurrentUser: () => apiRequest<{ user: UserProfile }>('/api/auth/me'),

  updateProfile: (displayName: string, preferences?: Record<string, unknown>) =>
    apiRequest<{ user: UserProfile }>('/api/auth/profile', {
      method: 'PUT',
      body: JSON.stringify({ displayName, preferences }),
    }),

  deleteAccount: async () => {
    const res = await apiRequest<{ deleted: boolean }>('/api/auth/account', {
      method: 'DELETE',
    });
    setAuthToken(null);
    try {
      await signOut(auth);
    } catch {
      // ignore
    }
    return res;
  },

  // Student Sessions & MCQ Engine
  startSession: (params: {
    mode: 'study' | 'exam' | 'custom';
    title?: string;
    subjectIds?: number[];
    lectureIds?: number[];
    difficulties?: string[];
    tagFilter?: string;
    requestedCount?: number;
    shuffleQuestions?: boolean;
    shuffleOptions?: boolean;
    avoidRecent?: boolean;
    timeLimitMinutes?: number | null;
  }) =>
    apiRequest<{ session: any; shortfallNotice: string | null }>('/api/sessions', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  getSession: (sessionId: number) =>
    apiRequest<{ session: any }>(`/api/sessions/${sessionId}`),

  submitQuestionAnswer: (
    sessionId: number,
    questionId: number,
    selectedOption: string | null,
    lockAnswer: boolean,
    elapsedSeconds?: number
  ) =>
    apiRequest<{ session: any }>(`/api/sessions/${sessionId}/answer`, {
      method: 'POST',
      body: JSON.stringify({
        questionId,
        selectedOption,
        lockAnswer,
        elapsedSeconds,
      }),
    }),

  completeSession: (
    sessionId: number,
    answers?: Record<number, string | null>,
    elapsedSeconds?: number
  ) =>
    apiRequest<{ session: any }>(`/api/sessions/${sessionId}/complete`, {
      method: 'POST',
      body: JSON.stringify({ answers, elapsedSeconds }),
    }),

  // Bookmarks & Dashboard
  getDashboard: () => apiRequest<any>('/api/dashboard'),

  getBookmarks: () =>
    apiRequest<{ bookmarks: any[]; answeredQuestions: any[] }>('/api/bookmarks'),

  toggleBookmark: (questionId: number, note?: string) =>
    apiRequest<{ bookmarked: boolean; questionId: number }>('/api/bookmarks/toggle', {
      method: 'POST',
      body: JSON.stringify({ questionId, note }),
    }),

  // Administrator Operations
  getAdminOverview: () => apiRequest<any>('/api/admin/overview'),

  saveSubject: (payload: any) =>
    apiRequest<{ subject: any }>('/api/admin/subjects', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  saveLecture: (payload: any) =>
    apiRequest<{ lecture: any }>('/api/admin/lectures', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  saveQuestion: (payload: any) =>
    apiRequest<{ question: any }>('/api/admin/questions', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  deleteSubject: (subjectId: number) =>
    apiRequest<{ action: string; message: string }>(
      `/api/admin/subjects/${subjectId}`,
      {
        method: 'DELETE',
      }
    ),

  deleteLecture: (lectureId: number) =>
    apiRequest<{ action: string; message: string }>(
      `/api/admin/lectures/${lectureId}`,
      {
        method: 'DELETE',
      }
    ),

  deleteQuestionBank: (bankId: number) =>
    apiRequest<{ action: string; message: string }>(
      `/api/admin/question-banks/${bankId}`,
      {
        method: 'DELETE',
      }
    ),

  deleteOrArchiveQuestion: (questionId: number) =>
    apiRequest<{ action: string; message: string }>(
      `/api/admin/questions/${questionId}`,
      {
        method: 'DELETE',
      }
    ),

  deleteSessionAdmin: (sessionId: number) =>
    apiRequest<{ action: string; message: string }>(
      `/api/admin/sessions/${sessionId}`,
      {
        method: 'DELETE',
      }
    ),

  updateUserRole: (targetUid: string, role: 'student' | 'admin') =>
    apiRequest<{ user: UserProfile; message: string }>(
      `/api/admin/users/${encodeURIComponent(targetUid)}/role`,
      {
        method: 'PUT',
        body: JSON.stringify({ role }),
      }
    ),

  deleteUserAdmin: (targetUid: string) =>
    apiRequest<{ action: string; message: string }>(
      `/api/admin/users/${encodeURIComponent(targetUid)}`,
      {
        method: 'DELETE',
      }
    ),

  previewCsvImport: (csvContent: string) =>
    apiRequest<any>('/api/admin/import/preview', {
      method: 'POST',
      body: JSON.stringify({ csvContent }),
    }),

  executeCsvImport: (fileName: string, csvContent: string) =>
    apiRequest<any>('/api/admin/import/execute', {
      method: 'POST',
      body: JSON.stringify({ fileName, csvContent }),
    }),

  exportQuestionBankCsv: async (): Promise<string> => {
    const headers: Record<string, string> = {};
    if (inMemoryAuthToken) {
      headers['Authorization'] = `Bearer ${inMemoryAuthToken}`;
    }
    const res = await fetch('/api/admin/export-csv', { headers });
    if (!res.ok) throw new Error('Failed to export CSV backup.');
    return res.text();
  },
};
