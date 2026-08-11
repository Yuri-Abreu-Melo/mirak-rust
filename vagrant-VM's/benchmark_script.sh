#!/bin/bash
# benchmark_script.sh – execute inside the VM

# Do not stop on non-zero exit codes; capture failures in the logs
set +e

RESULT_DIR="/vagrant/benchmarks/$(date +%Y%m%d_%H%M%S)_$(hostname)"
mkdir -p "$RESULT_DIR"

# ------------------------------------------------------------
# Run a benchmark command with sudo and log full output
# ------------------------------------------------------------
run_bench_sudo() {
    local cmd="$1"
    local label="$2"
    local full_log="$RESULT_DIR/${label}_full.log"

    echo "========================================" | tee -a "$full_log"
    echo "📊 Benchmark: $label (sudo)" | tee -a "$full_log"
    echo "🔧 Command: sudo $cmd" | tee -a "$full_log"
    echo "⏰ Start: $(date)" | tee -a "$full_log"
    echo "----------------------------------------" | tee -a "$full_log"

    sudo /usr/bin/time -v bash -c "$cmd" > >(tee -a "$full_log") 2>&1

    echo "----------------------------------------" | tee -a "$full_log"
    echo "✅ End: $(date)" | tee -a "$full_log"
    echo "" >> "$full_log"
}

# ------------------------------------------------------------
# Run a benchmark command as the normal vagrant user
# ------------------------------------------------------------
run_bench_user() {
    local cmd="$1"
    local label="$2"
    local full_log="$RESULT_DIR/${label}_full.log"

    echo "========================================" | tee -a "$full_log"
    echo "📊 Benchmark: $label (user)" | tee -a "$full_log"
    echo "🔧 Command: $cmd" | tee -a "$full_log"
    echo "⏰ Start: $(date)" | tee -a "$full_log"
    echo "----------------------------------------" | tee -a "$full_log"

    /usr/bin/time -v bash -c "$cmd" > >(tee -a "$full_log") 2>&1

    echo "----------------------------------------" | tee -a "$full_log"
    echo "✅ End: $(date)" | tee -a "$full_log"
    echo "" >> "$full_log"
}

# ------------------------------------------------------------
# Consolidate collected metrics into a CSV file
# ------------------------------------------------------------
consolidate_results() {
    local dir="$1"
    local csv_file="$dir/benchmark_summary.csv"
    local distro=$(hostname)

    echo "📊 Consolidating metrics into $csv_file ..."
    echo "distribution,tool,elapsed_seconds,user_cpu_seconds,system_cpu_seconds,cpu_percent,max_memory_mb,voluntary_context_switches,involuntary_context_switches,major_page_faults,minor_page_faults" > "$csv_file"

    for full_log in "$dir"/*_full.log; do
        [ -f "$full_log" ] || continue

        tool=$(basename "$full_log" | sed 's/_full\.log$//')

        elapsed_line=$(grep "Elapsed (wall clock) time" "$full_log" | head -1)
        if [ -n "$elapsed_line" ]; then
            elapsed_raw=$(echo "$elapsed_line" | awk -F': ' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -d ' ')
            elapsed_sec=$(echo "$elapsed_raw" | awk '
                /^[0-9]+:[0-9]+:[0-9]+\.[0-9]+$/ { split($0,a,":"); print a[1]*3600 + a[2]*60 + a[3] }
                /^[0-9]+:[0-9]+\.[0-9]+$/     { split($0,a,":"); print a[1]*60 + a[2] }
                /^[0-9]+\.[0-9]+$/            { print $0 }
                /^[0-9]+$/                    { print $0 }
            ')
            [ -z "$elapsed_sec" ] && elapsed_sec=""
        else
            elapsed_sec=""
        fi

        user_raw=$(grep "User time (seconds)" "$full_log" | head -1 | awk -F': ' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
        sys_raw=$(grep "System time (seconds)" "$full_log" | head -1 | awk -F': ' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
        cpu_raw=$(grep "Percent of CPU this job got" "$full_log" | head -1 | awk -F': ' '{print $2}' | sed 's/%//;s/^[ \t]*//;s/[ \t]*$//')
        max_rss_kb=$(grep "Maximum resident set size (kbytes)" "$full_log" | head -1 | awk -F': ' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
        vol_cs=$(grep "Voluntary context switches" "$full_log" | head -1 | awk -F': ' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
        invol_cs=$(grep "Involuntary context switches" "$full_log" | head -1 | awk -F': ' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
        major_pf=$(grep "Major (requiring I/O) page faults" "$full_log" | head -1 | awk -F': ' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
        minor_pf=$(grep "Minor (reclaiming a frame) page faults" "$full_log" | head -1 | awk -F': ' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')

        user_sec=$(echo "$user_raw" | awk '{printf "%.2f", $1}')
        sys_sec=$(echo "$sys_raw" | awk '{printf "%.2f", $1}')
        if [ -n "$elapsed_sec" ]; then
            elapsed_sec=$(echo "$elapsed_sec" | awk '{printf "%.2f", $1}')
        fi
        cpu_pct=$(echo "$cpu_raw" | awk '{printf "%.0f", $1}')
        if [ -n "$max_rss_kb" ] && [ "$max_rss_kb" -gt 0 ] 2>/dev/null; then
            max_rss_mb=$(echo "$max_rss_kb" | awk '{printf "%.1f", $1/1024}')
        else
            max_rss_mb=""
        fi

        echo "$distro,$tool,$elapsed_sec,$user_sec,$sys_sec,$cpu_pct,$max_rss_mb,$vol_cs,$invol_cs,$major_pf,$minor_pf" >> "$csv_file"
    done

    echo "✅ CSV summary generated at: $csv_file"
}

# ------------------------------------------------------------
# Start benchmark section
# ------------------------------------------------------------
echo "=========================================="
echo "🔥 Starting benchmarks on $(hostname)"
echo "📁 Results directory: $RESULT_DIR"
echo "=========================================="

run_bench_sudo "trivy fs / --scanners vuln --exit-code 0 --no-progress -f table --skip-files '**/*.pom' --skip-files '**/pom.xml' > \"$RESULT_DIR/trivy_report.txt\" 2>&1" "trivy"
run_bench_sudo "grype dir:/ --scope squashed -o table > \"$RESULT_DIR/grype_report.txt\" 2>&1" "grype"
run_bench_sudo "vuls scan && vuls report -format-full-text > \"$RESULT_DIR/vuls_report.txt\" 2>&1" "vuls"

if [ -x "/home/vagrant/mirak-app/mirak" ] && [ -f "/home/vagrant/mirak-app/api_key.txt" ]; then
    run_bench_user "/home/vagrant/mirak-app/mirak -f /home/vagrant/mirak-app/api_key.txt > \"$RESULT_DIR/mirak_report.txt\" 2>&1" "mirak"
else
    echo "⚠️  mirak or api_key.txt not found. Skipping mirak benchmark." | tee -a "$RESULT_DIR/erros.log"
fi

echo "=========================================="
echo "🏁 All benchmarks completed"
echo "📂 Results directory: $RESULT_DIR"
echo "=========================================="

consolidate_results "$RESULT_DIR"
echo "✅ Benchmark process finished. Summary CSV at: $RESULT_DIR/benchmark_summary.csv"
