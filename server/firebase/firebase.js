import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";

const firebaseConfig = {
  apiKey: "AIzaSyC0aUV4HMBCHGDLn8NvEv_SP2fXYOHimzo",
  authDomain: "keraza-2026-b05ea.firebaseapp.com",
  projectId: "keraza-2026-b05ea",
  storageBucket: "keraza-2026-b05ea.firebasestorage.app",
  messagingSenderId: "1056397508479",
  appId: "1:1056397508479:web:edfae922916ca1758d644a",
  measurementId: "G-DCELNZZNVG"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);