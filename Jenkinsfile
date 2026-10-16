// SPDX-License-Identifier: MIT
//
// Jenkinsfile — Deterministic AI Sandbox: CI/CD integration example.
//
// The pattern that matters:
//   1. the shield is attached on the HOST, not inside the container
//      (a runner-level privileged step; on Kubernetes this is a
//      DaemonSet that attaches per node and scopes per pod cgroup)
//   2. the agent stage joins the pinned cgroup
//   3. agent exit code becomes a security gate: 0 = nothing left the
//      host; non-zero = a policy decision fired, fail the build
//
// Runner prerequisites: kernel >= 5.15, CONFIG_BPF_LSM=y, `bpf` in the
// lsm= boot parameter, libbpf >= 0.5 (Ubuntu 22.04's 0.5 works; 24.04's 1.3 is known-good).

pipeline {
    agent { label 'ephemeral-runner' }

    stages {
        stage('Build sandbox') {
            steps { sh 'make' }
        }

        stage('AI agent — deterministically sandboxed') {
            steps {
                // attach the shield, scoped to this build's cgroup
                sh '''
                    CG=/sys/fs/cgroup/agent-${BUILD_TAG}
                    sudo mkdir -p $CG
                    sudo ./sandbox --cgroup $CG &
                    echo $! > sandbox.pid
                    sleep 1
                '''
                // run the agent INSIDE the pinned cgroup. Joining means
                // writing to cgroup.procs (root here, or delegate the
                // cgroup dir to the CI user). Any non-zero exit fails the
                // build: 3 = exfiltration observed, 2 = sandbox could
                // not engage (fail-closed — never a silent no-op).
                sh '''
                    sudo python3 src/agent.py --mode shielded \
                        --join-cgroup /sys/fs/cgroup/agent-${BUILD_TAG}
                '''
            }
            post {
                always {
                    // sandbox lifetime == run lifetime
                    sh 'sudo kill -INT $(cat sandbox.pid) || true'
                    sh 'sudo rmdir /sys/fs/cgroup/agent-${BUILD_TAG} || true'
                    // verdict events (JSON lines) are in the loader output
                    // above — ship them to your SIEM from the CI log
                }
            }
        }
    }
}
