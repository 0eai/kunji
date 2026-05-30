import { initializeApp } from 'firebase/app';
import { getFirestore } from 'firebase/firestore';

// Public web config for the project whose Functions handle this demo's sessions.
// (Reads the session doc to flip the page to "signed in" instantly via onSnapshot.)
const app = initializeApp({
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
});

export const db = getFirestore(app);
