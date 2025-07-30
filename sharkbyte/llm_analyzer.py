"""
LLM integration for SharkByte PCAP analyzer.
"""

import os
import json
from typing import Dict, List, Any, Optional
from openai import OpenAI
from .utils import save_results, load_results


class LLMAnalyzer:
    """
    Uses LLM to analyze PCAP patterns and provide intelligent insights.
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4"):
        self.model = model
        self.client = OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))
        
    def analyze_patterns(self, pattern_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use LLM to analyze detected patterns and provide insights.
        
        Args:
            pattern_results: Results from PatternDetector.detect_patterns
            
        Returns:
            Dictionary containing LLM analysis and insights
        """
        print("Analyzing patterns with LLM...")
        
        # Prepare data for LLM analysis
        analysis_data = self._prepare_analysis_data(pattern_results)
        
        # Generate LLM prompts
        prompts = self._generate_analysis_prompts(analysis_data)
        
        # Get LLM responses
        llm_insights = {}
        for prompt_name, prompt in prompts.items():
            try:
                response = self._get_llm_response(prompt)
                llm_insights[prompt_name] = response
            except Exception as e:
                print(f"Error getting LLM response for {prompt_name}: {str(e)}")
                llm_insights[prompt_name] = f"Error: {str(e)}"
        
        return {
            'llm_insights': llm_insights,
            'analysis_data': analysis_data
        }
    
    def _prepare_analysis_data(self, pattern_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare data for LLM analysis.
        
        Args:
            pattern_results: Pattern detection results
            
        Returns:
            Prepared analysis data
        """
        # Extract key information for LLM analysis
        analysis_data = {
            'common_keys': pattern_results.get('common_keys', []),
            'value_patterns_summary': {},
            'similar_patterns': pattern_results.get('similar_patterns', []),
            'hidden_identifiers': pattern_results.get('hidden_identifiers', []),
            'statistics': pattern_results.get('statistics', {})
        }
        
        # Summarize value patterns
        value_patterns = pattern_results.get('value_patterns', {})
        for key, pattern_info in value_patterns.items():
            analysis_data['value_patterns_summary'][key] = {
                'total_values': pattern_info.get('total_values', 0),
                'unique_values': pattern_info.get('unique_values', 0),
                'most_common_values': pattern_info.get('most_common_values', [])[:5],
                'patterns': pattern_info.get('patterns', {})
            }
        
        return analysis_data
    
    def _generate_analysis_prompts(self, analysis_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate prompts for different types of LLM analysis.
        
        Args:
            analysis_data: Prepared analysis data
            
        Returns:
            Dictionary mapping analysis types to prompts
        """
        prompts = {}
        
        # Overall pattern analysis
        prompts['overall_analysis'] = self._create_overall_analysis_prompt(analysis_data)
        
        # Hidden identifier analysis
        prompts['hidden_identifiers'] = self._create_hidden_identifiers_prompt(analysis_data)
        
        # Similar pattern analysis
        prompts['similar_patterns'] = self._create_similar_patterns_prompt(analysis_data)
        
        # Value pattern analysis
        prompts['value_patterns'] = self._create_value_patterns_prompt(analysis_data)
        
        # Security implications
        prompts['security_implications'] = self._create_security_implications_prompt(analysis_data)
        
        return prompts
    
    def _create_overall_analysis_prompt(self, analysis_data: Dict[str, Any]) -> str:
        """
        Create prompt for overall pattern analysis.
        
        Args:
            analysis_data: Analysis data
            
        Returns:
            Formatted prompt string
        """
        stats = analysis_data.get('statistics', {})
        
        prompt = f"""
You are an expert network security analyst analyzing PCAP (packet capture) files. 
I have analyzed {stats.get('files_analyzed', 0)} PCAP files and found the following patterns:

Key Statistics:
- Total keys found: {stats.get('total_keys', 0)}
- Unique keys: {stats.get('unique_keys', 0)}
- Total values: {stats.get('total_values', 0)}
- Unique values: {stats.get('unique_values', 0)}
- Average values per key: {stats.get('average_values_per_key', 0):.2f}

Common Keys Found: {analysis_data.get('common_keys', [])}

Please provide:
1. A high-level summary of what these patterns suggest about the network traffic
2. What types of network activity these patterns might indicate
3. Any potential security concerns or interesting findings
4. Recommendations for further investigation

Focus on identifying hidden connections, potential identifiers, and patterns that suggest related network activity.
"""
        return prompt
    
    def _create_hidden_identifiers_prompt(self, analysis_data: Dict[str, Any]) -> str:
        """
        Create prompt for hidden identifier analysis.
        
        Args:
            analysis_data: Analysis data
            
        Returns:
            Formatted prompt string
        """
        hidden_identifiers = analysis_data.get('hidden_identifiers', [])
        
        if not hidden_identifiers:
            return "No hidden identifiers were found in the analysis."
        
        prompt = f"""
I found {len(hidden_identifiers)} potential hidden identifiers across the PCAP files:

{json.dumps(hidden_identifiers, indent=2)}

Please analyze these hidden identifiers and provide:
1. What these values might represent (user IDs, session tokens, device identifiers, etc.)
2. The significance of finding the same value across multiple files
3. Potential security implications
4. How these could be used for network forensics or threat hunting
5. Recommendations for tracking these identifiers

Focus on identifying what these values might be used for and their significance in network analysis.
"""
        return prompt
    
    def _create_similar_patterns_prompt(self, analysis_data: Dict[str, Any]) -> str:
        """
        Create prompt for similar pattern analysis.
        
        Args:
            analysis_data: Analysis data
            
        Returns:
            Formatted prompt string
        """
        similar_patterns = analysis_data.get('similar_patterns', [])
        
        if not similar_patterns:
            return "No similar patterns were found in the analysis."
        
        prompt = f"""
I found {len(similar_patterns)} similar patterns across different keys in the PCAP files:

{json.dumps(similar_patterns, indent=2)}

Please analyze these similar patterns and provide:
1. What these similarities might indicate about the network protocols
2. Whether these patterns suggest related network activity
3. Potential implications for network analysis
4. How these patterns could be used for traffic classification
5. Recommendations for further investigation

Focus on understanding what these pattern similarities reveal about the network traffic structure.
"""
        return prompt
    
    def _create_value_patterns_prompt(self, analysis_data: Dict[str, Any]) -> str:
        """
        Create prompt for value pattern analysis.
        
        Args:
            analysis_data: Analysis data
            
        Returns:
            Formatted prompt string
        """
        value_patterns = analysis_data.get('value_patterns_summary', {})
        
        if not value_patterns:
            return "No value patterns were found in the analysis."
        
        # Select a few key examples for analysis
        key_examples = list(value_patterns.items())[:5]
        
        prompt = f"""
I analyzed value patterns for common keys across PCAP files. Here are some key examples:

{json.dumps(dict(key_examples), indent=2)}

Please analyze these value patterns and provide:
1. What these patterns suggest about the network traffic
2. Whether these patterns indicate normal or suspicious activity
3. How these patterns could be used for traffic analysis
4. Potential applications in network monitoring
5. Recommendations for pattern-based detection

Focus on understanding what these value distributions reveal about the network behavior.
"""
        return prompt
    
    def _create_security_implications_prompt(self, analysis_data: Dict[str, Any]) -> str:
        """
        Create prompt for security implications analysis.
        
        Args:
            analysis_data: Analysis data
            
        Returns:
            Formatted prompt string
        """
        stats = analysis_data.get('statistics', {})
        hidden_identifiers = analysis_data.get('hidden_identifiers', [])
        similar_patterns = analysis_data.get('similar_patterns', [])
        
        prompt = f"""
Based on the PCAP analysis with {stats.get('files_analyzed', 0)} files, {len(hidden_identifiers)} hidden identifiers, and {len(similar_patterns)} similar patterns, please provide a security analysis:

Key Findings:
- Hidden identifiers found: {len(hidden_identifiers)}
- Similar patterns detected: {len(similar_patterns)}
- Total unique values: {stats.get('unique_values', 0)}

Please provide:
1. Potential security implications of these findings
2. Whether these patterns suggest normal or suspicious network activity
3. Recommendations for security monitoring
4. How these patterns could be used for threat detection
5. Potential indicators of compromise (IoCs) that could be derived
6. Recommendations for network security posture

Focus on the security implications and potential threat hunting opportunities.
"""
        return prompt
    
    def _get_llm_response(self, prompt: str) -> str:
        """
        Get response from LLM.
        
        Args:
            prompt: Prompt to send to LLM
            
        Returns:
            LLM response
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert network security analyst with deep knowledge of PCAP analysis, network protocols, and cybersecurity. Provide clear, actionable insights based on the data provided."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=2000,
                temperature=0.3
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            return f"Error getting LLM response: {str(e)}"
    
    def generate_report(self, pattern_results: Dict[str, Any], llm_analysis: Dict[str, Any]) -> str:
        """
        Generate a comprehensive analysis report.
        
        Args:
            pattern_results: Pattern detection results
            llm_analysis: LLM analysis results
            
        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 80)
        report.append("SHARKBYTE PCAP ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Summary statistics
        stats = pattern_results.get('statistics', {})
        report.append("SUMMARY STATISTICS:")
        report.append(f"- Files analyzed: {stats.get('files_analyzed', 0)}")
        report.append(f"- Total keys: {stats.get('total_keys', 0)}")
        report.append(f"- Unique keys: {stats.get('unique_keys', 0)}")
        report.append(f"- Total values: {stats.get('total_values', 0)}")
        report.append(f"- Unique values: {stats.get('unique_values', 0)}")
        report.append("")
        
        # Key findings
        report.append("KEY FINDINGS:")
        report.append(f"- Common keys found: {len(pattern_results.get('common_keys', []))}")
        report.append(f"- Hidden identifiers: {len(pattern_results.get('hidden_identifiers', []))}")
        report.append(f"- Similar patterns: {len(pattern_results.get('similar_patterns', []))}")
        report.append("")
        
        # LLM insights
        llm_insights = llm_analysis.get('llm_insights', {})
        for insight_type, insight in llm_insights.items():
            report.append(f"{insight_type.upper().replace('_', ' ')}:")
            report.append("-" * 40)
            report.append(insight)
            report.append("")
        
        return "\n".join(report) 