# 🛡️ Security+ Nexus Core — SY0-701 Exam Prep

A complete, gamified study application for the CompTIA Security+ SY0-701 certification exam. Built as part of my cybersecurity career transition.

**🌐 Live App: [sectestprep.netlify.app](https://sectestprep.netlify.app)**

---

## ✨ Features

- **98 topics** covering all 5 exam domains with plain English analogies + technical detail
- **103+ quiz questions** with explanations and confidence-based spaced repetition
- **3 Performance-Based Question (PBQ) simulators** — firewall config, log analysis, incident response
- **Shadow Exam mode** — harder-than-real practice exams weighted by domain percentage
- **Gamification** — XP system, 10 ranks from Recruit 🐣 to Security+ Certified 🏆
- **Hands-on missions** — practical tasks mapped to each topic
- **Auto-save** — progress persists via localStorage

## 📊 Domain Coverage

| Domain | Weight | Topics | Status |
|--------|--------|--------|--------|
| 1. General Security Concepts | 12% | 18 | ✅ Complete |
| 2. Threats, Vulnerabilities & Mitigations | 22% | 30 | ✅ Complete |
| 3. Security Architecture | 18% | 17 | ✅ Complete |
| 4. Security Operations | 28% | 22 | ✅ Complete |
| 5. Security Program Management | 20% | 11 | ✅ Complete |

## 🚀 Run Locally

```bash
npx create-react-app nexus-core
cd nexus-core
# Replace src/App.js with the JSX file (rename function to App)
npm start
```

## 🏗️ Architecture

- **Decoupled JSON Content Engine** — all content in a single DB object, separated from UI
- **Modular design** — update content without touching components
- **React hooks** — useState, useCallback, useMemo for state management
- **localStorage persistence** — XP, progress, quiz history saved between sessions

## 📖 Study Strategy

1. Start with **Domain 4** (28% of exam — biggest chunk)
2. Then **Domain 2** (22%), **Domain 5** (20%), **Domain 3** (18%), **Domain 1** (12%)
3. Pair with [Professor Messer's free videos](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/) — topic IDs match
4. Add [Jason Dion's Udemy practice exams](https://www.udemy.com/) for question volume
5. Target **85%+ on Shadow Exams** before booking the real test

## 🛠️ Built With

- React 18
- Custom content engine designed from CompTIA SY0-701 exam objectives
- Built with AI assistance (Claude) for content generation and app development

---

*Part of my journey from Contract Engineer → Cybersecurity Professional*
