pipeline {
    agent any
    stages {
        stage('Clonar código') {
            steps {
                script {
                    checkout scm
                }
            }
        }
        stage('Construir imagen Docker') {
            steps {
                sh 'docker build -t mi_app .'
            }
        }
        stage('Ejecutar contenedor') {
            steps {
                sh 'docker run -d -p 5050:5050 --name mi_app_container mi_app'
            }
        }
        stage('Verificar contenedores') {
            steps {
                sh 'docker ps -a'
            }
        }
    }
}