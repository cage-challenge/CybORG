from CybORG.Evaluation.evaluation import run_evaluation

# this imports a submission data
from CybORG.Evaluation.submission.submission import submission_name, submission_team, submission_technique

if __name__ == "__main__":
    name = submission_name
    team = submission_team
    technique = submission_technique
    run_evaluation(name, team, technique, max_eps=1000, write_to_file=False)
