# SharkByte GUI Guide

SharkByte provides two different GUI interfaces to make PCAP analysis accessible and user-friendly.

## 🖥️ GUI Options

### 1. Web GUI (Gradio) - Recommended
A modern web-based interface with advanced features.

**Features:**
- 🌐 Web-based interface accessible from any browser
- 📊 Interactive visualizations and charts
- 🔗 Public sharing capabilities
- 📱 Mobile-friendly responsive design
- 🎨 Modern UI with themes

**Launch:**
```bash
# Using main.py
python main.py --gui

# Using dedicated launcher
python launch_gui.py

# Custom port
python launch_gui.py --port 8080

# Public sharing
python launch_gui.py --share
```

**Requirements:**
```bash
pip install gradio==4.7.1
```

### 2. Simple GUI (Tkinter) - Fallback Option
A lightweight desktop application for users with audio dependency issues.

**Features:**
- 🖥️ Native desktop application
- 📁 File browser integration
- 💾 Save results directly
- 📊 Open visualizations folder
- ⚡ No audio dependencies

**Launch:**
```bash
# Using main.py
python main.py --simple-gui

# Direct execution
python sharkbyte/simple_gui.py
```

**Requirements:**
- Built-in with Python (no additional dependencies)

## 🚀 Quick Start

### For Web GUI Users:
1. Install dependencies: `pip install -r requirements.txt`
2. Launch: `python main.py --gui`
3. Open browser to: `http://localhost:7860`
4. Enter PCAP folder path and API key
5. Click "Start Analysis"

### For Simple GUI Users:
1. Launch: `python main.py --simple-gui`
2. Use "Browse" button to select PCAP folder
3. Enter OpenAI API key (optional)
4. Configure analysis options
5. Click "Start Analysis"

## 📋 GUI Features

### Input Configuration
- **PCAP Folder Selection**: Browse or enter path to PCAP files
- **OpenAI API Key**: Optional for LLM analysis
- **Model Selection**: Choose between GPT-4 and GPT-3.5-turbo
- **Similarity Threshold**: Adjust pattern detection sensitivity (0.1-1.0)
- **Analysis Options**: Enable/disable LLM analysis and visualizations

### Analysis Process
- **Progress Tracking**: Real-time progress updates
- **Background Processing**: Non-blocking analysis
- **Error Handling**: Clear error messages and recovery options

### Results Display
- **Summary Statistics**: Files analyzed, packets processed, etc.
- **Key Findings**: Common keys, hidden identifiers, similar patterns
- **LLM Insights**: AI-powered analysis and recommendations
- **Export Options**: Save results as JSON files

### Visualization
- **Charts and Graphs**: Protocol distributions, file sizes, patterns
- **Interactive Plots**: Network graphs, heatmaps, clusters
- **HTML Reports**: Comprehensive analysis reports
- **Folder Access**: Direct access to visualization files

## 🔧 Troubleshooting

### Web GUI Issues:
- **Audio Dependencies**: If you get audio-related errors, use the simple GUI instead
- **Port Conflicts**: Change port with `--port 8080`
- **Network Access**: Use `--host 127.0.0.1` for local-only access

### Simple GUI Issues:
- **Tkinter Not Available**: Usually built-in with Python
- **Display Issues**: Check your desktop environment
- **File Permissions**: Ensure write access for saving results

### Common Solutions:
1. **"Gradio not available"**: Install with `pip install gradio`
2. **"No PCAP files found"**: Check folder path and file extensions (.pcap, .pcapng, .cap)
3. **"LLM analysis failed"**: Check OpenAI API key and internet connection
4. **"Visualization errors"**: Check matplotlib and plotly installation

## 🎯 Usage Tips

### For Network Analysts:
- Use similarity threshold 0.7-0.9 for most cases
- Enable LLM analysis for detailed insights
- Generate visualizations for presentations
- Save results for later comparison

### For Security Researchers:
- Focus on hidden identifiers for threat hunting
- Use pattern similarity for malware detection
- Enable verbose output for detailed logs
- Export results for further analysis

### For Beginners:
- Start with simple GUI for easier setup
- Use default settings initially
- Enable visualizations for better understanding
- Read the generated HTML reports

## 📊 Output Examples

### Web GUI Output:
- Interactive dashboard with real-time updates
- Gallery of visualizations
- Downloadable results and reports
- Shareable public links

### Simple GUI Output:
- Text-based results summary
- Local visualization files
- JSON export capabilities
- Direct folder access

## 🔗 Integration

Both GUIs integrate seamlessly with the command-line interface:
- Same analysis engine
- Compatible output formats
- Shared configuration options
- Consistent results

## 📈 Performance

### Web GUI:
- **Pros**: Modern interface, sharing capabilities, mobile access
- **Cons**: Audio dependencies, network requirements

### Simple GUI:
- **Pros**: Lightweight, no dependencies, fast startup
- **Cons**: Basic interface, desktop-only

Choose the GUI that best fits your needs and environment! 