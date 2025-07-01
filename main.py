# Project 1's main()
# Daniel S Cochran
# https://github.com/Alderon714/network_share_analyzer
#
# June 27, 2025 

from network_share_analyzer import * # import all from the main source dump

def main():
    print("Hello from network-share-analyzer!")

    parser = argparse.ArgumentParser(description='Analyze network share structure and security')
    parser.add_argument('share_path', help='Path to network share')
    parser.add_argument('--output-dir', default='analysis_output', 
                       help='Output directory for reports')
    parser.add_argument('--max-depth', type=int, 
                       help='Maximum directory depth to scan')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Create analyzer
    analyzer = NetworkShareAnalyzer(args.share_path, args.output_dir)
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Run analysis
        report_files = analyzer.run_analysis(args.max_depth)
        
        print("\nAnalysis Complete!")
        print(f"Reports generated in: {args.output_dir}")
        print("\nGenerated files:")
        for name, path in report_files.items():
            print(f"  - {name}: {path}")
            
    except Exception as e:
        print(f"Error during analysis: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    exit(main())