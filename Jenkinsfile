pipeline {
  /* Use docker image from tools/build-env folder */
  agent {
    dockerfile {
      filename 'Dockerfile_ubuntu_2404'
      dir 'tools/build-env'
      args '--mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock -u 0:0'
    }
  }

  environment {
    /* Collect versions saved in tools/ folder */
    FULL_VERSION = sh(script: "./tools/get_version.sh full", returnStdout: true).trim()
    SHORT_VERSION = sh(script: "./tools/get_version.sh", returnStdout: true).trim()
    BRANCH_FOLDER = sh(script: "./tools/get_branch_folder.sh ${BRANCH_NAME}", returnStdout: true).trim()
    RUST_STATIC_FLAGS = '-C target-feature=-crt-static'
  }

  stages {
    stage('Download prerequisites') {
      steps {
        dir('ttg') {
          git url: 'https://github.com/maximmenshikov/ttg.git',
              branch: 'main'
        }
      }
    }
    stage('Perform checks') {
      stages {
        stage("Fixes/formatting") {
          steps {
            /* Mark directory as safe - we might have dubious permissions here due to uid manipulations */
            sh 'git config --global --add safe.directory "*"'

            /* Fail if 'cargo fix' changes anything */
            sh 'cargo fix && git diff --exit-code'

            /* Fail if 'cargo fmt' changes anything */
            sh 'cargo fmt && git diff --exit-code'

            /* Fail if Cargo.toml is not updated with current version */
            sh 'cat Cargo.toml | grep ${SHORT_VERSION}'
          }
        }

        stage("Check version in Git tags") {
          when {
            expression {
              BRANCH_NAME == 'main'
            }
          }
          steps {
            /* Fail if tag is not updated with current version */
            sh 'git tag | grep ${SHORT_VERSION}'
          }
        }
      }
    }
    stage('Build for all platforms') {
      parallel {
        stage('Build (Linux)') {
          steps {
            sh 'which cargo'
            sh 'env RUSTFLAGS="${RUST_STATIC_FLAGS}" CROSS_CONTAINER_UID=0 CROSS_CONTAINER_GID=0 CROSS_CONTAINER_IN_CONTAINER=true CROSS_NO_WARNINGS=0 cross build --target=x86_64-unknown-linux-gnu --release'
            sh 'chmod -R 777 target'
          }
        }
      }
    }

    stage('Prepare bundle') {
      stages {
        /* Right now, we build just for Linux, that's the preferred platform */
        stage('Prepare artifacts (branch)') {
          steps {
            sh 'mkdir -p build && (rm -rf build/* || true)'
            /* Create branch-build-linux and doc-branch-build */
            sh './tools/release.sh --out build/isabelle-plugin-security-${BRANCH_FOLDER}-${BUILD_NUMBER}-linux-x86_64.tar.xz'
            /* Copy branch-build-linux to branch-latest-linux */
            sh 'cp build/isabelle-plugin-security-${BRANCH_FOLDER}-${BUILD_NUMBER}-linux-x86_64.tar.xz build/isabelle-plugin-security-${BRANCH_FOLDER}-latest-linux-x86_64.tar.xz'
          }
        }
        stage('Prepare artifacts (versioned)') {
          when {
            expression {
              BRANCH_NAME == 'main'
            }
          }
          steps {
            /* Create versioned artifacts */
            sh 'mkdir -p build/versioned_artifacts'

            /* Copy branch-latest-linux to fullver-linux */
            sh 'cp build/isabelle-plugin-security-${BRANCH_FOLDER}-latest-linux-x86_64.tar.xz build/versioned_artifacts/isabelle-plugin-security-${FULL_VERSION}-linux-x86_64.tar.xz'
          }
        }
      }
    }
    stage('Publish artifacts') {
      parallel {
        stage('Publish artifacts (branch)') {
          steps {
            ftpPublisher alwaysPublishFromMaster: true,
                         continueOnError: false,
                         failOnError: false,
                         masterNodeName: '',
                         paramPublish: null,
                         publishers: [
                          [
                            configName: 'isabelle-plugin-security',
                            transfers:
                              [[
                                asciiMode: false,
                                cleanRemote: false,
                                excludes: '',
                                flatten: false,
                                makeEmptyDirs: false,
                                noDefaultExcludes: false,
                                patternSeparator: '[, ]+',
                                remoteDirectory: "branches/${BRANCH_FOLDER}-${BUILD_NUMBER}",
                                remoteDirectorySDF: false,
                                removePrefix: 'build',
                                sourceFiles: "build/isabelle-plugin-security-*${BRANCH_FOLDER}-${BUILD_NUMBER}*.tar.xz"
                              ]],
                            usePromotionTimestamp: false,
                            useWorkspaceInPromotion: false,
                            verbose: true
                          ]
                        ]
            ftpPublisher alwaysPublishFromMaster: true,
                         continueOnError: false,
                         failOnError: false,
                         masterNodeName: '',
                         paramPublish: null,
                         publishers: [
                          [
                            configName: 'isabelle-plugin-security',
                            transfers:
                              [[
                                asciiMode: false,
                                cleanRemote: false,
                                excludes: '',
                                flatten: false,
                                makeEmptyDirs: false,
                                noDefaultExcludes: false,
                                patternSeparator: '[, ]+',
                                remoteDirectory: "branches/${BRANCH_FOLDER}",
                                remoteDirectorySDF: false,
                                removePrefix: 'build',
                                sourceFiles: "build/isabelle-plugin-security-*${BRANCH_FOLDER}-latest*.tar.xz"
                              ]],
                            usePromotionTimestamp: false,
                            useWorkspaceInPromotion: false,
                            verbose: true
                          ]
                        ]
          }
        }
        stage('Publish artifacts (versioned)') {
          when {
            expression {
              BRANCH_NAME == 'main'
            }
          }
          steps {
            ftpPublisher alwaysPublishFromMaster: true,
                         continueOnError: false,
                         failOnError: false,
                         masterNodeName: '',
                         paramPublish: null,
                         publishers: [
                          [
                            configName: 'isabelle-plugin-security',
                            transfers:
                              [[
                                asciiMode: false,
                                cleanRemote: false,
                                excludes: '',
                                flatten: false,
                                makeEmptyDirs: false,
                                noDefaultExcludes: false,
                                patternSeparator: '[, ]+',
                                remoteDirectory: "${FULL_VERSION}",
                                remoteDirectorySDF: false,
                                removePrefix: 'build/versioned_artifacts',
                                sourceFiles: "build/versioned_artifacts/isabelle-plugin-security-*.tar.xz"
                              ]],
                            usePromotionTimestamp: false,
                            useWorkspaceInPromotion: false,
                            verbose: true
                          ]
                        ]
          }
        }
        stage('Archive artifacts for Jenkins') {
          steps {
            archiveArtifacts artifacts: 'build/isabelle-plugin-security-*.tar.xz'
          }
        }
      }
    }
  }
  post {
    /* Send notification to Telegram */
    success {
      sh './ttg/ttg_send_notification --env --ignore-bad -- "${JOB_NAME}/${BUILD_NUMBER}: PASSED"'
    }
    failure {
      sh './ttg/ttg_send_notification --env --ignore-bad -- "${JOB_NAME}/${BUILD_NUMBER}: FAILED. See details in ${BUILD_URL}"'
    }
    always {
      sh 'chmod -R 777 target'
      sh 'chmod -R 777 build'
    }
  }
}
