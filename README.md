# SharkByte - LLM-Powered PCAP Analyzer

SharkByte is an intelligent packet analyzer that uses LLM (Large Language Model) technology to identify patterns and hidden identifiers across Wireshark PCAP files.

## Features

- **PCAP File Analysis**: Analyzes multiple PCAP files from a specified folder
- **Pattern Detection**: Identifies similar key-value pairs across different files
- **Hidden Identifier Discovery**: Finds patterns that suggest hidden connections between files
- **LLM-Powered Analysis**: Uses OpenAI's GPT models to understand packet patterns
- **Statistical Analysis**: Provides statistical insights about packet similarities
- **Visualization**: Generates charts and graphs showing pattern relationships
- **Web GUI Interface**: User-friendly web interface built with Gradio

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd SharkByte
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env and add your OpenAI API key
```

## Usage

### Basic Usage
```bash
python main.py --pcap-folder /path/to/pcap/files --output results.json
```

### Advanced Usage
```bash
python main.py \
    --pcap-folder /path/to/pcap/files \
    --output results.json \
    --model gpt-4 \
    --similarity-threshold 0.8 \
    --max-patterns 100
```

### GUI Interfaces

#### Web GUI (Gradio)
```bash
# Launch the web GUI
python main.py --gui

# Or use the dedicated launcher
python launch_gui.py

# Launch on specific port
python launch_gui.py --port 8080

# Create public link for sharing
python launch_gui.py --share
```

#### Simple GUI (Tkinter)
```bash
# Launch the simple GUI (no audio dependencies)
python main.py --simple-gui

# Or run directly
python sharkbyte/simple_gui.py
```

## Configuration

Create a `.env` file with the following variables:
```
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4
SIMILARITY_THRESHOLD=0.8
MAX_PATTERNS=100
```

## Output

The analyzer generates:
- JSON file with detected patterns
- CSV file with statistical data
- HTML report with visualizations
- Console output with key findings

## Project Structure

```
SharkByte/
├── main.py                 # Main entry point
├── launch_gui.py          # GUI launcher
├── test_sharkbyte.py      # Test script
├── sharkbyte/
│   ├── __init__.py
│   ├── analyzer.py        # Core PCAP analyzer
│   ├── llm_analyzer.py    # LLM integration
│   ├── pattern_detector.py # Pattern detection logic
│   ├── visualizer.py      # Visualization tools
│   ├── gui.py            # Gradio web interface
│   └── utils.py           # Utility functions
├── requirements.txt
├── README.md
└── env_example.txt
```

## License

MIT License 