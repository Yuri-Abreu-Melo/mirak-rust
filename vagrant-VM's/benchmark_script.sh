#!/bin/bash
# benchmark_script.sh – with elapsed time (elapsed_sec)

set +e

RESULT_DIR="/vagrant/benchmarks/$(date +%Y%m%d_%H%M%S)_$(hostname)"
mkdir -p "$RESULT_DIR"

# ------------------------------------------------------------
# Process monitoring function (with relative time)
# ------------------------------------------------------------
monitor_process() {
    local tool="$1"
    local output_file="$2"
    local use_sudo="$3"
    local parent_pid="$4"

    (
        local start_time=$(date +%s)
        local empty_count=0

        while true; do
            if ! kill -0 "$parent_pid" 2>/dev/null; then
                sleep 1
                break
            fi

            local pids
            if [ "$use_sudo" = "sudo" ]; then
                pids=$(sudo ps -C "$tool" -o pid= --no-headers 2>/dev/null | tr '\n' ' ')
                if [ -z "$pids" ] && command -v pgrep &>/dev/null; then
                    pids=$(sudo pgrep -f "$tool" 2>/dev/null | tr '\n' ' ')
                fi
                if [ -z "$pids" ]; then
                    pids=$(sudo ps aux | grep -E "[0-9]+ +[0-9.]+ +[0-9.]+ +[0-9]+ +.*$tool" | grep -v grep | awk '{print $2}' | tr '\n' ' ')
                fi
            else
                pids=$(ps -C "$tool" -o pid= --no-headers 2>/dev/null | tr '\n' ' ')
                if [ -z "$pids" ] && command -v pgrep &>/dev/null; then
                    pids=$(pgrep -f "$tool" 2>/dev/null | tr '\n' ' ')
                fi
                if [ -z "$pids" ]; then
                    pids=$(ps aux | grep -E "[0-9]+ +[0-9.]+ +[0-9.]+ +[0-9]+ +.*$tool" | grep -v grep | awk '{print $2}' | tr '\n' ' ')
                fi
            fi

            if [ -z "$pids" ]; then
                empty_count=$((empty_count + 1))
                if [ $empty_count -ge 3 ]; then
                    break
                fi
                sleep 0.5
                continue
            else
                empty_count=0
            fi

            local stats
            if [ "$use_sudo" = "sudo" ]; then
                stats=$(sudo ps -p $pids -o %cpu=,rss=,vsz= --no-headers 2>/dev/null | awk '
                    { cpu += $1; rss += $2; vsz += $3 }
                    END { printf "%.1f %.2f %.2f", cpu, rss/1024, vsz/1024 }
                ')
            else
                stats=$(ps -p $pids -o %cpu=,rss=,vsz= --no-headers 2>/dev/null | awk '
                    { cpu += $1; rss += $2; vsz += $3 }
                    END { printf "%.1f %.2f %.2f", cpu, rss/1024, vsz/1024 }
                ')
            fi

            if [ -z "$stats" ]; then
                break
            fi

            local now=$(date +%s)
            local elapsed=$((now - start_time))
            echo "$now $elapsed $stats" >> "$output_file"
            sleep 1
        done
    ) &
}

# ------------------------------------------------------------
# Function to run a benchmark
# ------------------------------------------------------------
run_bench() {
    local cmd="$1"
    local label="$2"
    local timeseries="$RESULT_DIR/${label}_timeseries.csv"

    # Header with columns: timestamp_abs, elapsed_sec, cpu_pct, rss_mb, vsz_mb
    echo "timestamp_abs,elapsed_sec,cpu_pct,rss_mb,vsz_mb" > "$timeseries"

    echo "========================================"
    echo "📊 Benchmark: $label"
    echo "🔧 Command: $cmd"
    echo "⏰ Start: $(date)"
    echo "----------------------------------------"

    eval "$cmd" &
    local bench_pid=$!
    sleep 2

    monitor_process "$label" "$timeseries" "sudo" "$bench_pid" &
    local monitor_pid=$!

    wait "$bench_pid"
    local exit_code=$?

    kill -TERM "$monitor_pid" 2>/dev/null
    wait "$monitor_pid" 2>/dev/null

    echo "----------------------------------------"
    echo "✅ End: $(date) (exit code: $exit_code)"
    echo "📈 Time series saved to: $timeseries"
    echo ""
}

# ------------------------------------------------------------
# START OF BENCHMARKS
# ------------------------------------------------------------
echo "=========================================="
echo "🔥 Starting benchmarks on $(hostname)"
echo "📁 Results in: $RESULT_DIR"
echo "=========================================="

run_bench "sudo trivy fs / --scanners vuln --exit-code 0 --no-progress -f table > \"$RESULT_DIR/trivy_report.txt\" 2>&1" "trivy"

run_bench "sudo grype dir:/ --scope squashed -o table > \"$RESULT_DIR/grype_report.txt\" 2>&1" "grype"

run_bench "sudo vuls scan && sudo vuls report -format-full-text > \"$RESULT_DIR/vuls_report.txt\" 2>&1" "vuls"

if [ -x "/home/vagrant/mirak-app/mirak" ] && [ -f "/home/vagrant/mirak-app/api_key.txt" ]; then
    run_bench "/home/vagrant/mirak-app/mirak -f /home/vagrant/mirak-app/api_key.txt > \"$RESULT_DIR/mirak_report.txt\" 2>&1" "mirak"
else
    echo "⚠️  mirak or api_key.txt not found. Skipping." | tee -a "$RESULT_DIR/errors.log"
fi

echo "=========================================="
echo "🏁 All benchmarks completed!"
echo "📂 Results in: $RESULT_DIR"
echo "   - *_report.txt        → raw tool report"
echo "   - *_timeseries.csv    → timestamp_abs, elapsed_sec, cpu_pct, rss_mb, vsz_mb"
echo "=========================================="