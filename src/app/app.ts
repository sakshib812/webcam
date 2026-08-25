import { Component, signal, computed, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

export interface LanguageOption {
  id: string;
  name: string;
  greeting: string;
  flag: string;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App implements OnInit, OnDestroy {
  // Signals for reactive application state
  readonly userName = signal<string>('World');
  readonly selectedLangId = signal<string>('en');
  readonly counter = signal<number>(1);
  readonly activeTheme = signal<string>('default');
  readonly activeCodeTab = signal<'ts' | 'html' | 'css'>('ts');
  readonly isCopied = signal<boolean>(false);
  readonly currentTime = signal<string>('');
  readonly isSpeaking = signal<boolean>(false);

  private timerId: any;

  // Language directory
  readonly languages: LanguageOption[] = [
    { id: 'en', name: 'English', greeting: 'Hello World', flag: '🇺🇸' },
    { id: 'es', name: 'Spanish', greeting: '¡Hola Mundo!', flag: '🇪🇸' },
    { id: 'fr', name: 'French', greeting: 'Bonjour le monde!', flag: '🇫🇷' },
    { id: 'de', name: 'German', greeting: 'Hallo Welt!', flag: '🇩🇪' },
    { id: 'ja', name: 'Japanese', greeting: 'こんにちは世界！', flag: '🇯🇵' },
    { id: 'hi', name: 'Hindi', greeting: 'नमस्ते दुनिया!', flag: '🇮🇳' },
    { id: 'it', name: 'Italian', greeting: 'Ciao Mondo!', flag: '🇮🇹' },
    { id: 'pt', name: 'Portuguese', greeting: 'Olá Mundo!', flag: '🇵🇹' }
  ];

  // Computed signals
  readonly currentLang = computed(() => 
    this.languages.find(l => l.id === this.selectedLangId()) || this.languages[0]
  );

  readonly doubleCounter = computed(() => this.counter() * 2);

  readonly fullGreeting = computed(() => {
    const lang = this.currentLang();
    const name = this.userName().trim() || 'World';
    
    if (name.toLowerCase() === 'world') {
      return lang.greeting;
    }

    switch (lang.id) {
      case 'es': return `¡Hola, ${name}!`;
      case 'fr': return `Bonjour, ${name}!`;
      case 'de': return `Hallo, ${name}!`;
      case 'ja': return `こんにちは、${name}さん！`;
      case 'hi': return `नमस्ते, ${name}!`;
      case 'it': return `Ciao, ${name}!`;
      case 'pt': return `Olá, ${name}!`;
      default: return `Hello, ${name}!`;
    }
  });

  ngOnInit() {
    this.updateClock();
    this.timerId = setInterval(() => this.updateClock(), 1000);
  }

  ngOnDestroy() {
    if (this.timerId) {
      clearInterval(this.timerId);
    }
  }

  private updateClock() {
    const now = new Date();
    this.currentTime.set(now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
  }

  setLanguage(langId: string) {
    this.selectedLangId.set(langId);
  }

  setTheme(themeName: string) {
    this.activeTheme.set(themeName);
    if (themeName === 'default') {
      document.body.removeAttribute('data-theme');
    } else {
      document.body.setAttribute('data-theme', themeName);
    }
  }

  incrementCounter() {
    this.counter.update(n => n + 1);
  }

  decrementCounter() {
    this.counter.update(n => Math.max(0, n - 1));
  }

  resetCounter() {
    this.counter.set(0);
  }

  setCodeTab(tab: 'ts' | 'html' | 'css') {
    this.activeCodeTab.set(tab);
  }

  speakGreeting() {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      const textToSpeak = this.fullGreeting();
      const utterance = new SpeechSynthesisUtterance(textToSpeak);
      
      const langMap: Record<string, string> = {
        en: 'en-US', es: 'es-ES', fr: 'fr-FR', de: 'de-DE', 
        ja: 'ja-JP', hi: 'hi-IN', it: 'it-IT', pt: 'pt-BR'
      };
      
      utterance.lang = langMap[this.selectedLangId()] || 'en-US';
      utterance.rate = 0.9;

      this.isSpeaking.set(true);
      utterance.onend = () => this.isSpeaking.set(false);
      utterance.onerror = () => this.isSpeaking.set(false);

      window.speechSynthesis.speak(utterance);
    }
  }

  copyCodeSnippet() {
    const snippets = {
      ts: `import { Component, signal } from '@angular/core';

@Component({
  selector: 'app-root',
  standalone: true,
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  readonly greeting = signal('Hello World');
}`,
      html: `<main class="container">
  <h1>{{ greeting() }}</h1>
  <button (click)="speak()">Say Hello</button>
</main>`,
      css: `h1 {
  font-family: 'Outfit', sans-serif;
  background: linear-gradient(135deg, #e02e4e, #00f2fe);
  -webkit-background-clip: text;
  color: transparent;
}`
    };

    const code = snippets[this.activeCodeTab()];
    navigator.clipboard.writeText(code).then(() => {
      this.isCopied.set(true);
      setTimeout(() => this.isCopied.set(false), 2200);
    });
  }
}
