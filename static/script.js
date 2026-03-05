// ============================================
// FORENCOMMUNITY - SCRIPT PRINCIPAL UNIFICADO (VERSIÓN FLASK)
// ============================================

const FC = {
  // ==========================================
  // 1. HERRAMIENTAS EXISTENTES (MEJORADAS CON FLASK)
  // ==========================================

  // --- Chequeador de correo (AHORA CON API REAL) ---
  setupEmailChecker: function(formId, inputId, resultId) {
    const form = document.getElementById(formId);
    const input = document.getElementById(inputId);
    const result = document.getElementById(resultId);

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = input.value.trim();

      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        result.innerHTML = "⚠️ Ingresa un correo válido.";
        return;
      }

      result.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verificando en múltiples fuentes...';

      try {
        const response = await fetch('/api/check-email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            email: email,
            deepSearch: true 
          })
        });

        const data = await response.json();

        if (data.error) {
          result.innerHTML = `❌ ${data.error}`;
          return;
        }

        let html = '';
        
        if (data.total_breaches === 0) {
          html = `
            <div class="alert alert-success">
              <i class="fas fa-check-circle"></i>
              <strong>¡Buenas noticias!</strong> No encontramos tu correo en filtraciones.
            </div>
          `;
        } else {
          html = `
            <div class="alert alert-danger">
              <i class="fas fa-exclamation-triangle"></i>
              <strong>¡Alerta!</strong> Tu correo aparece en ${data.total_breaches} filtración(es).
            </div>
            <div style="margin-top: 15px;">
              ${data.breaches.map(b => `
                <div style="background: #fee2e2; padding: 10px; margin-bottom: 10px; border-radius: 8px;">
                  <strong>${b.name}</strong> (${b.date})<br>
                  <small>Datos expuestos: ${b.data}</small>
                </div>
              `).join('')}
            </div>
          `;
        }

        html += `
          <div style="margin-top: 15px;">
            <p><strong>Recomendaciones:</strong></p>
            <ul>
              ${data.recommendations ? data.recommendations.map(r => `<li>${r}</li>`).join('') : '<li>Cambia tu contraseña</li><li>Activa la autenticación de dos factores</li>'}
            </ul>
          </div>
          <div style="margin-top: 15px; text-align: center;">
            <a href="https://haveibeenpwned.com/account/${encodeURIComponent(email)}" target="_blank" class="btn btn-outline">
              <i class="fas fa-external-link-alt"></i> Verificar en Have I Been Pwned
            </a>
          </div>
        `;

        result.innerHTML = html;

      } catch (error) {
        result.innerHTML = `❌ Error en la verificación: ${error.message}`;
      }
    });
  },

  // --- Generador de contraseñas (AHORA CON API REAL) ---
  generarPassword: async function(outputId, options = {}) {
    try {
      const response = await fetch('/api/generate-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          length: options.length || 16,
          cantidad: options.cantidad || 1,
          options: {
            mayusculas: options.mayus !== false,
            minusculas: options.minus !== false,
            numeros: options.numeros !== false,
            simbolos: options.simbolos || false,
            evitarAmbiguos: options.evitarAmbiguos || false,
            separador: options.separador || false
          }
        })
      });

      const data = await response.json();
      
      if (data.error) {
        alert(`❌ ${data.error}`);
        return;
      }

      if (data.passwords && data.passwords.length > 0) {
        document.getElementById(outputId).value = data.passwords[0].password;
        
        const strengthBar = document.getElementById('strengthBar');
        if (strengthBar) {
          strengthBar.style.width = data.passwords[0].strength + '%';
        }
        
        return data.passwords[0].password;
      }
    } catch (error) {
      console.error('Error generando contraseña:', error);
      return this.fallbackGenerarPassword(outputId, options);
    }
  },

  fallbackGenerarPassword: function(outputId, options = {}) {
    const length = options.length || 12;
    const useMayus = options.mayus !== false;
    const useMinus = options.minus !== false;
    const useNumeros = options.numeros !== false;
    const useSimbolos = options.simbolos || false;
    
    let chars = '';
    if (useMinus) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (useMayus) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useNumeros) chars += '0123456789';
    if (useSimbolos) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    if (chars === '') chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    
    let password = "";
    for (let i = 0; i < length; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    document.getElementById(outputId).value = password;
    return password;
  },

  // Analizar contraseña con API
  analizarPassword: async function(password) {
    try {
      const response = await fetch('/api/analyze-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Error analizando contraseña:', error);
      return null;
    }
  },

  // ==========================================
  // 5. ENCRIPTADOR AVANZADO (NUEVO CON FLASK)
  // ==========================================

  Encryptor: {
    currentAlgorithm: 'base64',
    currentKey: '',
    currentShift: 3,
    history: [],

    init: function() {
      console.log('🔐 Inicializando Encriptador Avanzado...');
      this.loadHistory();
      this.initEventListeners();
    },

    // Cargar historial
    loadHistory: function() {
      try {
        this.history = JSON.parse(localStorage.getItem('encryptHistory') || '[]');
      } catch {
        this.history = [];
      }
    },

    // Guardar en historial
    saveToHistory: function(input, output, algorithm) {
      this.history.unshift({
        input: input.substring(0, 30) + (input.length > 30 ? '...' : ''),
        output: output.substring(0, 30) + (output.length > 30 ? '...' : ''),
        algorithm: algorithm,
        date: new Date().toLocaleString()
      });

      if (this.history.length > 10) this.history.pop();
      localStorage.setItem('encryptHistory', JSON.stringify(this.history));
      this.updateHistoryDisplay();
    },

    // Actualizar historial en UI
    updateHistoryDisplay: function() {
      const list = document.getElementById('history-list');
      if (!list) return;

      if (this.history.length === 0) {
        list.innerHTML = '<li class="history-item" style="text-align: center;">No hay operaciones guardadas</li>';
        return;
      }

      list.innerHTML = this.history.map(item => `
        <li class="history-item">
          <div>
            <strong>${item.algorithm}</strong><br>
            <small>${item.date}</small>
          </div>
          <span class="history-badge" style="background: var(--primary); color: white; padding: 4px 8px; border-radius: 4px;">
            ${item.input} → ${item.output}
          </span>
        </li>
      `).join('');
    },

    // Limpiar historial
    clearHistory: function() {
      this.history = [];
      localStorage.removeItem('encryptHistory');
      this.updateHistoryDisplay();
      FC.showNotification('🗑️ Historial limpiado', 'info');
    },

    // Exportar historial
    exportHistory: function() {
      if (this.history.length === 0) {
        FC.showNotification('No hay historial para exportar', 'warning');
        return;
      }

      const blob = new Blob([JSON.stringify(this.history, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `historial-encriptador-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      FC.showNotification('✅ Historial exportado', 'success');
    },

    // Encriptar texto
    encrypt: async function(text, method, key = '', shift = 3) {
      if (!text) {
        FC.showNotification('Por favor ingresa un texto', 'warning');
        return null;
      }

      try {
        const response = await fetch('/api/encrypt', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text: text,
            method: method,
            key: key,
            shift: shift
          })
        });

        const data = await response.json();
        
        if (data.error) {
          FC.showNotification(data.error, 'error');
          return null;
        }

        return data.encrypted;
      } catch (error) {
        console.error('Error encriptando:', error);
        FC.showNotification('Error al conectar con el servidor', 'error');
        return null;
      }
    },

    // Desencriptar texto
    decrypt: async function(text, method, key = '', shift = 3) {
      if (!text) {
        FC.showNotification('Por favor ingresa un texto', 'warning');
        return null;
      }

      try {
        const response = await fetch('/api/decrypt', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text: text,
            method: method,
            key: key,
            shift: shift
          })
        });

        const data = await response.json();
        
        if (data.error) {
          FC.showNotification(data.error, 'error');
          return null;
        }

        return data.decrypted;
      } catch (error) {
        console.error('Error desencriptando:', error);
        FC.showNotification('Error al conectar con el servidor', 'error');
        return null;
      }
    },

    // Comparar hashes
    compareHashes: function(hash1, hash2) {
      if (!hash1 || !hash2) {
        FC.showNotification('Ingresa ambos hashes', 'warning');
        return null;
      }

      const cleanHash1 = hash1.replace(/\s+/g, '').toLowerCase();
      const cleanHash2 = hash2.replace(/\s+/g, '').toLowerCase();

      return {
        match: cleanHash1 === cleanHash2,
        hash1: cleanHash1,
        hash2: cleanHash2
      };
    },

    // Analizar hash
    analyzeHash: function(hash) {
      if (!hash) return null;

      const length = hash.length;
      let type = 'Desconocido';
      let bits = 0;

      if (length === 32 && /^[a-f0-9]+$/i.test(hash)) {
        type = 'MD5 (128 bits)';
        bits = 128;
      } else if (length === 40 && /^[a-f0-9]+$/i.test(hash)) {
        type = 'SHA1 (160 bits)';
        bits = 160;
      } else if (length === 64 && /^[a-f0-9]+$/i.test(hash)) {
        type = 'SHA256 (256 bits)';
        bits = 256;
      } else if (length === 128 && /^[a-f0-9]+$/i.test(hash)) {
        type = 'SHA512 (512 bits)';
        bits = 512;
      } else if (length === 8 && /^[a-f0-9]+$/i.test(hash)) {
        type = 'CRC32 (32 bits)';
        bits = 32;
      } else if (/^[A-Za-z0-9+/=]+$/.test(hash)) {
        type = 'Base64';
      } else if (/^[A-Z2-7]+=*$/.test(hash)) {
        type = 'Base32';
      }

      return {
        length: length,
        type: type,
        bits: bits,
        isHex: /^[a-f0-9]+$/i.test(hash),
        isBase64: /^[A-Za-z0-9+/=]+$/.test(hash),
        isBase32: /^[A-Z2-7]+=*$/.test(hash)
      };
    },

    // Actualizar estadísticas
    updateStats: function(input, output) {
      const inputLength = document.getElementById('input-length');
      const outputLength = document.getElementById('output-length');
      const ratio = document.getElementById('ratio');

      if (inputLength) inputLength.textContent = input.length;
      if (outputLength) outputLength.textContent = output.length;
      
      if (ratio && input.length > 0) {
        const ratioValue = ((output.length / input.length) * 100).toFixed(1);
        ratio.textContent = ratioValue + '%';
      }
    },

    // Inicializar event listeners
    initEventListeners: function() {
      // Auto-actualizar estadísticas
      const texto = document.getElementById('texto');
      if (texto) {
        texto.addEventListener('input', () => {
          const output = document.getElementById('resultado')?.textContent;
          if (output) this.updateStats(texto.value, output);
        });
      }
    }
  },

  // ==========================================
  // 2. ANALIZADOR DE RED PRO (CON DATOS REALES)
  // ==========================================

  NetworkAnalyzer: {
    connections: [],
    socket: null,
    charts: {},
    threats: [],
    autoUpdate: null,
    
    init: function() {
      console.log('📡 Inicializando Network Analyzer con Flask...');
      this.cargarDatosReales();
      this.initEventListeners();
      this.initHeatmap();
      this.iniciarAutoActualizacion();
    },
    
    cargarDatosReales: async function() {
      try {
        const response = await fetch('/api/conexiones-reales');
        const data = await response.json();
        
        if (data.error) {
          console.error('Error:', data.error);
          this.loadEducationalData();
          return;
        }
        
        if (data.length > 0) {
          this.renderConexionesReales(data);
          this.updateStatsFromReal(data);
          this.updateHeatmapWithRealData(data);
        }
      } catch (error) {
        console.error('Error cargando datos reales:', error);
        this.loadEducationalData();
      }
    },
    
    renderConexionesReales: function(conexiones) {
      const container = document.getElementById('connections-list');
      if (!container) return;
      
      let html = '';
      conexiones.forEach(conn => {
        const riesgoColor = {
          'bajo': '#10B981',
          'medio': '#F59E0B',
          'alto': '#EF4444'
        };
        
        html += `
          <div class="connection-item risk-${conn.riesgo}">
            <div class="app-info">
              <i class="fas fa-microchip"></i>
              <div>
                <span style="font-weight: 600;">${conn.app}</span>
                <br><small>PID: ${conn.pid || 'N/A'}</small>
              </div>
            </div>
            <div>${conn.ip_remota}</div>
            <div>${conn.estado || 'Establecida'}</div>
            <div>
              <span style="background: ${riesgoColor[conn.riesgo]}; padding: 4px 8px; border-radius: 4px; color: white;">
                ${conn.riesgo.toUpperCase()}
              </span>
            </div>
            <div><span class="flag-icon flag-icon-${conn.pais?.toLowerCase() || 'us'}"></span> ${conn.pais || '??'}</div>
          </div>
        `;
      });
      
      container.innerHTML = html;
    },
    
    updateStatsFromReal: function(conexiones) {
      const total = document.getElementById('total-connections');
      const safe = document.getElementById('safe-connections');
      const warning = document.getElementById('warning-connections');
      const danger = document.getElementById('danger-connections');
      
      if (total) total.textContent = conexiones.length;
      if (safe) safe.textContent = conexiones.filter(c => c.riesgo === 'bajo').length;
      if (warning) warning.textContent = conexiones.filter(c => c.riesgo === 'medio').length;
      if (danger) danger.textContent = conexiones.filter(c => c.riesgo === 'alto').length;
    },
    
    updateHeatmapWithRealData: function(conexiones) {
      const canvas = document.getElementById('portHeatmap');
      if (!canvas) return;
      
      const ctx = canvas.getContext('2d');
      const width = canvas.width;
      const height = canvas.height;
      
      ctx.clearRect(0, 0, width, height);
      
      const portCounts = {};
      conexiones.forEach(conn => {
        if (conn.ip_remota && conn.ip_remota !== 'Escuchando') {
          const match = conn.ip_remota.match(/:(\d+)/);
          if (match) {
            const port = match[1];
            portCounts[port] = (portCounts[port] || 0) + 1;
          }
        }
      });
      
      const ports = Object.keys(portCounts);
      if (ports.length === 0) {
        this.initHeatmap();
        return;
      }
      
      const maxCount = Math.max(...Object.values(portCounts));
      const cellWidth = width / ports.length;
      
      ports.forEach((port, index) => {
        const x = index * cellWidth;
        const count = portCounts[port];
        const intensity = count / maxCount;
        const barHeight = intensity * (height - 60);
        
        const portNum = parseInt(port);
        let color = '#10B981';
        
        if ([21, 23, 25, 445, 3389].includes(portNum)) {
          color = '#EF4444';
        } else if ([80, 8080, 8000].includes(portNum)) {
          color = '#F59E0B';
        }
        
        ctx.fillStyle = color;
        ctx.fillRect(x + 5, height - 40 - barHeight, cellWidth - 10, barHeight);
        
        ctx.fillStyle = '#333';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(port, x + cellWidth/2, height - 15);
        ctx.fillText(count, x + cellWidth/2, height - 45 - barHeight);
      });
    },
    
    iniciarAutoActualizacion: function() {
      if (this.autoUpdate) clearInterval(this.autoUpdate);
      this.autoUpdate = setInterval(() => this.cargarDatosReales(), 5000);
    },
    
    exportReport: async function() {
      try {
        const connections = Array.from(document.querySelectorAll('.connection-item')).map(item => {
          return {
            app: item.querySelector('.app-info span')?.textContent || 'Unknown',
            dest: item.children[1]?.textContent || 'Unknown',
            risk: item.className.match(/risk-(\w+)/)?.[1] || 'unknown'
          };
        });
        
        const report = {
          fecha: new Date().toISOString(),
          total_conexiones: connections.length,
          conexiones: connections,
          estadisticas: {
            seguras: connections.filter(c => c.risk === 'low' || c.risk === 'bajo').length,
            advertencias: connections.filter(c => c.risk === 'medium' || c.risk === 'medio').length,
            peligrosas: connections.filter(c => c.risk === 'high' || c.risk === 'alto').length
          }
        };
        
        const statsRes = await fetch('/api/estadisticas-red');
        if (statsRes.ok) {
          const stats = await statsRes.json();
          report.estadisticas_red = stats;
        }
        
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `reporte-red-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        
        FC.showNotification('✅ Reporte exportado con estadísticas reales', 'success');
        
      } catch (error) {
        console.error('Error exportando reporte:', error);
        FC.showNotification('Error exportando reporte', 'error');
      }
    },
    
    initHeatmap: function() {
      const canvas = document.getElementById('portHeatmap');
      if (!canvas) return;
      
      const ctx = canvas.getContext('2d');
      const width = canvas.width;
      const height = canvas.height;
      
      ctx.clearRect(0, 0, width, height);
      
      const portData = [
        { port: 21, freq: 5, risk: 'high' },
        { port: 22, freq: 8, risk: 'low' },
        { port: 23, freq: 3, risk: 'high' },
        { port: 25, freq: 4, risk: 'medium' },
        { port: 80, freq: 20, risk: 'low' },
        { port: 443, freq: 25, risk: 'low' },
        { port: 445, freq: 6, risk: 'high' },
        { port: 3389, freq: 7, risk: 'medium' },
        { port: 8080, freq: 12, risk: 'low' },
        { port: 8443, freq: 9, risk: 'low' }
      ];
      
      const maxFreq = Math.max(...portData.map(d => d.freq));
      const cellWidth = width / portData.length;
      
      portData.forEach((data, index) => {
        const x = index * cellWidth;
        const cellHeight = height - 60;
        
        let color;
        if (data.risk === 'high') {
          color = '#EF4444';
        } else if (data.risk === 'medium') {
          color = '#F59E0B';
        } else {
          color = '#10B981';
        }
        
        const barHeight = (data.freq / maxFreq) * cellHeight;
        
        ctx.fillStyle = color;
        ctx.fillRect(x + 5, height - 40 - barHeight, cellWidth - 10, barHeight);
        ctx.strokeStyle = '#ddd';
        ctx.strokeRect(x + 5, height - 40 - barHeight, cellWidth - 10, barHeight);
        
        ctx.fillStyle = '#333';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(data.port, x + cellWidth/2, height - 15);
        ctx.fillText(`${data.freq}`, x + cellWidth/2, height - 50);
      });
      
      ctx.fillStyle = '#333';
      ctx.font = '14px Arial';
      ctx.textAlign = 'center';
      ctx.fillText('Frecuencia y Riesgo de Puertos', width/2, 25);
    },
    
    loadEducationalData: function() {
      const connectionsList = document.getElementById('connections-list');
      if (!connectionsList) return;
      
      connectionsList.innerHTML = '<div class="loading">Cargando datos educativos...</div>';
      
      setTimeout(() => {
        const data = this.getSampleData();
        this.renderConnections(data);
        this.updateStats(data);
      }, 1000);
    },
    
    getSampleData: function() {
      return {
        safe: [
          { app: "Google Chrome", icon: "fab fa-chrome", dest: "google.com", traffic: "1.2MB", risk: "low" },
          { app: "Spotify", icon: "fab fa-spotify", dest: "spotify.com", traffic: "0.8MB", risk: "low" },
          { app: "Discord", icon: "fab fa-discord", dest: "discord.com", traffic: "0.5MB", risk: "low" }
        ],
        warning: [
          { app: "Torrent Client", icon: "fas fa-download", dest: "p2p-network", traffic: "15MB", risk: "medium" }
        ],
        danger: [
          { app: "Unknown Process", icon: "fas fa-skull", dest: "malicious.ru", traffic: "8MB", risk: "high" }
        ]
      };
    },
    
    renderConnections: function(data) {
      const container = document.getElementById('connections-list');
      if (!container) return;
      
      let html = '';
      [...data.safe, ...data.warning, ...data.danger].forEach(conn => {
        html += this.createConnectionRow(conn);
      });
      
      container.innerHTML = html;
    },
    
    createConnectionRow: function(conn) {
      const riskColor = {
        low: '#10B981',
        medium: '#F59E0B',
        high: '#EF4444'
      };
      
      return `
        <div class="connection-item risk-${conn.risk}">
          <div class="app-info">
            <i class="${conn.icon}"></i>
            <span>${conn.app}</span>
          </div>
          <div>${conn.dest}</div>
          <div>${conn.traffic}</div>
          <div>
            <span style="background: ${riskColor[conn.risk]}; padding: 4px 8px; border-radius: 4px; color: white;">
              ${conn.risk.toUpperCase()}
            </span>
          </div>
        </div>
      `;
    },
    
    updateStats: function(data) {
      const total = document.getElementById('total-connections');
      const safe = document.getElementById('safe-connections');
      const warning = document.getElementById('warning-connections');
      const danger = document.getElementById('danger-connections');
      
      if (total) total.textContent = data.safe.length + data.warning.length + data.danger.length;
      if (safe) safe.textContent = data.safe.length;
      if (warning) warning.textContent = data.warning.length;
      if (danger) danger.textContent = data.danger.length;
    },
    
    initEventListeners: function() {
      const startBtn = document.getElementById('start-live-simulation');
      if (startBtn) {
        startBtn.addEventListener('click', () => this.startLiveSimulation());
      }
      
      const exportBtn = document.getElementById('export-report');
      if (exportBtn) {
        exportBtn.addEventListener('click', () => this.exportReport());
      }
    },
    
    startLiveSimulation: function() {
      console.log('🎮 Iniciando simulación en vivo...');
      let counter = 0;
      
      const interval = setInterval(() => {
        if (counter >= 10) {
          clearInterval(interval);
          return;
        }
        
        const newConn = {
          app: `Proceso ${Math.floor(Math.random() * 100)}`,
          icon: 'fas fa-microchip',
          dest: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          traffic: `${Math.floor(Math.random() * 10)}MB`,
          risk: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)]
        };
        
        this.addConnectionLive(newConn);
        counter++;
      }, 2000);
    },
    
    addConnectionLive: function(conn) {
      const container = document.getElementById('connections-list');
      if (!container) return;
      
      const row = this.createConnectionRow(conn);
      container.insertAdjacentHTML('afterbegin', row);
      
      if (container.children.length > 20) {
        container.removeChild(container.lastChild);
      }
      
      const currentConnections = Array.from(container.children).map(child => {
        const riskClass = child.className.match(/risk-(\w+)/);
        return { risk: riskClass ? riskClass[1] : 'low' };
      });
      
      const stats = {
        safe: currentConnections.filter(c => c.risk === 'low').length,
        warning: currentConnections.filter(c => c.risk === 'medium').length,
        danger: currentConnections.filter(c => c.risk === 'high').length
      };
      
      document.getElementById('total-connections').textContent = currentConnections.length;
      document.getElementById('safe-connections').textContent = stats.safe;
      document.getElementById('warning-connections').textContent = stats.warning;
      document.getElementById('danger-connections').textContent = stats.danger;
      
      if (conn.risk === 'high') {
        this.showThreatAlert(conn);
      }

      this.updateHeatmapWithConnections();
    },
    
    showThreatAlert: function(conn) {
      const alerts = document.getElementById('alerts-container');
      if (!alerts) return;
      
      const alert = document.createElement('div');
      alert.className = 'alert-popup';
      alert.innerHTML = `
        <div style="background: #EF4444; color: white; padding: 10px; border-radius: 4px; margin-bottom: 10px;">
          <strong>🚨 AMENAZA DETECTADA</strong><br>
          ${conn.app} - ${conn.dest}
        </div>
      `;
      
      alerts.appendChild(alert);
      setTimeout(() => alert.remove(), 5000);
    },
    
    updateHeatmapWithConnections: function() {
      const canvas = document.getElementById('portHeatmap');
      if (!canvas) return;
      
      const ctx = canvas.getContext('2d');
      const width = canvas.width;
      const height = canvas.height;
      
      ctx.clearRect(0, 0, width, height);
      
      const portCounts = {};
      const connections = document.querySelectorAll('.connection-item');
      
      connections.forEach(conn => {
        const destText = conn.children[1]?.textContent || '';
        const portMatch = destText.match(/:(\d+)/);
        
        if (portMatch) {
          const port = portMatch[1];
          portCounts[port] = (portCounts[port] || 0) + 1;
        }
      });
      
      if (Object.keys(portCounts).length === 0) {
        this.initHeatmap();
        return;
      }
      
      const ports = Object.keys(portCounts);
      const maxCount = Math.max(...Object.values(portCounts));
      const cellWidth = width / ports.length;
      
      ports.forEach((port, index) => {
        const x = index * cellWidth;
        const count = portCounts[port];
        const intensity = count / maxCount;
        
        const portNum = parseInt(port);
        let color;
        if ([21, 23, 135, 139, 445].includes(portNum)) {
          color = '#EF4444';
        } else if ([25, 110, 3389].includes(portNum)) {
          color = '#F59E0B';
        } else {
          color = '#10B981';
        }
        
        const barHeight = intensity * (height - 80);
        
        ctx.fillStyle = color;
        ctx.fillRect(x + 5, height - 50 - barHeight, cellWidth - 10, barHeight);
        
        ctx.fillStyle = '#333';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(port, x + cellWidth/2, height - 20);
        ctx.fillText(`${count}`, x + cellWidth/2, height - 70);
      });
    }
  },

  // ==========================================
  // 3. VERIFICADOR DE TELÉFONO
  // ==========================================

  setupPhoneChecker: function(formId, inputId, resultId) {
    const form = document.getElementById(formId);
    const input = document.getElementById(inputId);
    const result = document.getElementById(resultId);

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const phone = input.value.trim();

      if (!phone || phone.length < 8) {
        result.innerHTML = "⚠️ Ingresa un número válido (mínimo 8 dígitos)";
        return;
      }

      result.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analizando número...';

      try {
        const response = await fetch('/api/check-phone', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ phone })
        });

        const data = await response.json();

        if (data.error) {
          result.innerHTML = `❌ ${data.error}`;
          return;
        }

        const riesgoColor = {
          'bajo': '#10B981',
          'medio': '#F59E0B', 
          'alto': '#EF4444'
        };

        result.innerHTML = `
          <div style="background: #f8fafc; padding: 20px; border-radius: 8px;">
            <h4 style="color: var(--primary); margin-bottom: 15px;">Resultados del análisis:</h4>
            <p><strong>📞 Número:</strong> ${data.phone}</p>
            <p><strong>🌍 País:</strong> ${data.country}</p>
            <p><strong>📡 Operadora:</strong> ${data.carrier}</p>
            <p><strong>📱 Tipo:</strong> ${data.line_type}</p>
            <p>
              <strong>⚠️ Nivel de riesgo:</strong> 
              <span style="background: ${riesgoColor[data.risk_level]}; color: white; padding: 4px 8px; border-radius: 4px;">
                ${data.risk_level.toUpperCase()}
              </span>
            </p>
            <p><strong>📊 Puntuación de riesgo:</strong> ${data.risk_score}/100</p>
            ${data.reasons && data.reasons.length > 0 ? `
              <div style="margin-top: 15px;">
                <strong>Motivos:</strong>
                <ul>
                  ${data.reasons.map(r => `<li>${r}</li>`).join('')}
                </ul>
              </div>
            ` : ''}
            <p><small>Reportes de usuarios: ${data.reports || 0}</small></p>
          </div>
        `;

      } catch (error) {
        result.innerHTML = `❌ Error en la verificación: ${error.message}`;
      }
    });
  },

  // ==========================================
  // 4. ESTADÍSTICAS GLOBALES
  // ==========================================

  cargarEstadisticasGlobales: async function() {
    try {
      const response = await fetch('/api/global-stats');
      const data = await response.json();
      
      const elementos = {
        'globalBreaches': data.total_breaches,
        'globalEmails': data.total_emails,
        'globalAccounts': data.vulnerable_accounts,
        'globalThreats': data.active_threats,
        'globalAttacks': data.daily_attacks
      };
      
      for (let [id, valor] of Object.entries(elementos)) {
        const el = document.getElementById(id);
        if (el) el.textContent = valor;
      }
      
    } catch (error) {
      console.error('Error cargando estadísticas globales:', error);
    }
  },

  // ==========================================
  // 6. UTILIDADES GENERALES
  // ==========================================

  showNotification: function(message, type = 'info', duration = 3000) {
    let container = document.getElementById('alertContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'alertContainer';
      container.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
      `;
      document.body.appendChild(container);
    }
    
    const notification = document.createElement('div');
    notification.style.cssText = `
      padding: 15px 20px;
      margin-bottom: 10px;
      border-radius: 8px;
      color: white;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 10px;
      animation: slideIn 0.3s ease;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    `;
    
    const colors = {
      'error': '#EF4444',
      'success': '#10B981',
      'warning': '#F59E0B',
      'info': '#3B82F6'
    };
    
    notification.style.background = colors[type] || colors.info;
    
    const icons = {
      'error': 'fa-exclamation-circle',
      'success': 'fa-check-circle',
      'warning': 'fa-exclamation-triangle',
      'info': 'fa-info-circle'
    };
    
    notification.innerHTML = `<i class="fas ${icons[type]}"></i> ${message}`;
    container.appendChild(notification);
    
    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease';
      setTimeout(() => notification.remove(), 300);
    }, duration);
  },

  copyToClipboard: async function(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    let text = element.value || element.textContent;
    
    try {
      await navigator.clipboard.writeText(text);
      this.showNotification('✅ Copiado al portapapeles', 'success');
    } catch (err) {
      element.select();
      document.execCommand('copy');
      this.showNotification('✅ Copiado al portapapeles', 'success');
    }
  },

  init: function() {
    console.log('🚀 FORENCOMMUNITY - Script inicializado (Modo Flask)');
    
    this.cargarEstadisticasGlobales();
    
    if (document.getElementById('connections-list')) {
      this.NetworkAnalyzer.init();
    }
    
    if (document.getElementById('email-checker-form')) {
      this.setupEmailChecker('email-checker-form', 'email-input', 'email-result');
    }
    
    if (document.getElementById('phone-checker-form')) {
      this.setupPhoneChecker('phone-checker-form', 'phone-input', 'phone-result');
    }
    
    // Inicializar encriptador
    this.Encryptor.init();
    
    this.initTooltips();
  },

  initTooltips: function() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    tooltips.forEach(el => {
      el.addEventListener('mouseenter', (e) => {
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = e.target.dataset.tooltip;
        tooltip.style.cssText = `
          position: absolute;
          background: #333;
          color: white;
          padding: 5px 10px;
          border-radius: 4px;
          font-size: 0.9rem;
          z-index: 1000;
        `;
        document.body.appendChild(tooltip);
        
        const rect = e.target.getBoundingClientRect();
        tooltip.style.top = rect.top - tooltip.offsetHeight - 5 + 'px';
        tooltip.style.left = rect.left + (rect.width/2) - (tooltip.offsetWidth/2) + 'px';
        
        e.target.addEventListener('mouseleave', () => tooltip.remove(), { once: true });
      });
    });
  }
};

// ============================================
// INICIALIZACIÓN AUTOMÁTICA
// ============================================
document.addEventListener('DOMContentLoaded', () => {
  FC.init();
});

// ============================================
// ANIMACIONES CSS
// ============================================
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  
  @keyframes slideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
  }
  
  @keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.7; }
    100% { opacity: 1; }
  }
  
  .connection-item {
    transition: all 0.3s ease;
    display: grid;
    grid-template-columns: 2fr 2fr 1fr 1fr 0.5fr;
    gap: 10px;
    padding: 15px;
    border-bottom: 1px solid #e5e7eb;
  }
  
  .connection-item:hover {
    transform: translateX(5px);
    background: #f8fafc;
  }
  
  .risk-low { border-left: 4px solid #10B981; }
  .risk-medium { border-left: 4px solid #F59E0B; }
  .risk-high { border-left: 4px solid #EF4444; }
  
  .alert-popup {
    animation: slideIn 0.3s ease;
    margin-bottom: 10px;
  }
  
  .flag-icon {
    width: 20px;
    height: 15px;
    display: inline-block;
    background-size: cover;
  }
  
  .loading {
    text-align: center;
    padding: 30px;
  }
  
  .loading-spinner {
    border: 4px solid #f3f3f3;
    border-top: 4px solid var(--primary);
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 1s linear infinite;
    margin: 0 auto 15px;
  }
  
  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }
  
  .tooltip {
    position: absolute;
    background: #333;
    color: white;
    padding: 5px 10px;
    border-radius: 4px;
    font-size: 0.9rem;
    pointer-events: none;
    z-index: 1000;
    animation: fadeIn 0.2s ease;
  }
  
  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }
`;
document.head.appendChild(style);