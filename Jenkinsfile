node('win10') {
    git 'https://github.com/g0t4/jenkins2-course-spring-boot.git'
    
    //bat label: 'win10', script: 'mvn -f spring-boot-samples/spring-boot-sample-atmosphere/pom.xml clean package'
    def project_path = "spring-boot-samples/spring-boot-sample-atmosphere"
    dir(project_path) {
        bat 'mvn clean package'
        archiveArtifacts "target/*.jar"
    }

}
