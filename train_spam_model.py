#!/usr/bin/env python3
"""
Train Naive Bayes spam classifier on SMS Spam Collection dataset.
Run: python train_spam_model.py
Output: Email Extension/spam_model.json
"""
import json
import math
import re
import os
from collections import defaultdict

def tokenize(text):
    """Tokenize text into words (lowercase, alphanumeric)."""
    text = re.sub(r'[^a-z0-9\s]', ' ', text.lower())
    return [w for w in text.split() if len(w) > 1]

# Embedded training data: spam patterns + SMS Spam Collection (UCI) samples - public domain
# Format: (label, message) - spam=1, ham=0
TRAINING_DATA = [
    ("spam", "Free entry in 2 a wkly comp to win FA Cup final tkts 21st May 2005. Text FA to 87121 to receive entry question(std txt rate)T&C's apply 08452810075over18's"),
    ("spam", "WINNER!! As a valued network customer you have been selected to receivea £900 prize reward! To claim call 09061701461. Claim code KL341. Valid 12 hours only."),
    ("spam", "Had your mobile 11 months or more? U R entitled to Update to the latest colour mobiles with camera for Free! Call The Mobile Update Co FREE on 08002986030"),
    ("spam", "SIX chances to win CASH! From 100 to 20,000 pounds txt> CSH11 and send to 87575. Cost 150p/day, 6(max 180p/week). 16+ T&C Apply. Reply HL 4 info"),
    ("spam", "Urgent! Your Mobile No was awarded a £2,000 Bonus Prize call 09066364589"),
    ("spam", "Send me otp"),
    ("spam", "Please send me your OTP to verify"),
    ("spam", "Your bank account has been locked. Verify your identity at http://bit.ly/bank-secure"),
    ("spam", "Congratulations! You have won $1,000,000. Claim now at tinyurl.com/prize"),
    ("spam", "Urgent: Your card has been blocked. Call 09061234567 immediately with your CVV"),
    ("spam", "Double your money! Investment opportunity. Guaranteed returns. Reply YES"),
    ("spam", "Free gift card! Click here: goo.gl/abc123 to claim your $500 Amazon gift card"),
    ("spam", "Transfer 5000 rupees to account 1234567890 to unlock your prize"),
    ("spam", "Verify your account now. Your KYC update required. Click link or account suspended"),
    ("spam", "Bitcoin investment - 10x returns in 30 days. Limited spots. Act now"),
    ("spam", "You have inherited 2 million dollars. Contact us for transfer. Keep confidential"),
    ("spam", "Act now! Limited time offer. Send money to secure your package"),
    ("spam", "Your OTP is 123456. Do not share with anyone. Reply if you did not request"),
    ("spam", "Apple iTune gift card needed. Send $200 in cards. Urgent."),
    ("spam", "Western Union wire transfer required. Pay the fee to receive your inheritance"),
    ("spam", "Account verify needed. Confirm your identity. Link: bit.ly/verify-now"),
    ("spam", "You won the lottery! Prize money 50000 INR. Send bank details to claim"),
    ("spam", "Urgent action required. Your account will be closed in 5 minutes"),
    ("spam", "Double your investment. Crypto opportunity. Reply YES to get started"),
    ("spam", "Unclaimed funds. Foreign account. Transfer fee 500 USD. Contact immediately"),
    ("spam", "Verify OTP sent to your number. One time password required for security"),
    ("spam", "Send me the verification code you received"),
    ("spam", "Your debit card is locked. Share PIN to unlock"),
    ("spam", "Credit card verification. Enter CVV at t.co/secure"),
    ("spam", "Bank account suspended. IFSC verification required. Act now"),
    ("spam", "Google Play card $100. Send code to receive your reward"),
    ("ham", "Go until jurong point, crazy.. Available only in bugis n great world la e buffet..."),
    ("ham", "Ok lar... Joking wif u oni..."),
    ("ham", "Free msg Hey there darling it's been 3 week's now and no word back! I'd like some fun you up for it still? Tb ok! XxX chg to 2 recieve"),
    ("ham", "U dun say so early hor... U c already then say..."),
    ("ham", "Nah I don't think he goes to usf, he lives around here though"),
    ("ham", "Even my brother is not like to speak with me. They treat me like aids patent."),
    ("ham", "As per your request 'Melle Melle (Oru Minaminunginte Nurungu Vettam)' has been set as your callertune for all Callers. Press *9 to copy your friends Callertune"),
    ("spam", "WINNER!! As a valued network customer you have been selected to receivea £900 prize reward! To claim call 09061701461. Claim code KL341. Valid 12 hours only."),
    ("spam", "Had your mobile 11 months or more? U R entitled to Update to the latest colour mobiles with camera for Free! Call The Mobile Update Co FREE on 08002986030"),
    ("ham", "I'm gonna be home soon and i don't want to talk about this stuff anymore tonight, k? I've cried enough today."),
    ("ham", "Svar act wis contact. reply graded Le/enquiries"),
    ("ham", "Will u meet me tomorrow?"),
    ("ham", "Thanks for your reply. The meeting is scheduled for 3pm."),
    ("ham", "I'll call you later. Can you pick up groceries?"),
    ("ham", "Project deadline is next Friday. Please submit your report."),
    ("ham", "Lunch at 1pm? Let me know if that works."),
    ("ham", "Meeting moved to conference room B."),
    ("ham", "Thanks for the update. See you tomorrow."),
    ("ham", "Can you send me the document when you get a chance?"),
    ("ham", "The weather is nice today. Want to go for a walk?"),
    ("ham", "Reminder: Team standup at 10am."),
    ("ham", "Please review the attached proposal."),
    ("ham", "I've finished the analysis. Ready to discuss."),
    ("ham", "Flight lands at 6pm. Can you pick me up?"),
    ("ham", "Dinner at 7? I'll make reservations."),
    ("ham", "The report looks good. Minor edits needed."),
    ("ham", "Happy birthday! Hope you have a great day."),
    ("ham", "Let me know your availability for next week."),
    ("ham", "I received your email. Will respond by EOD."),
    ("spam", "Click here to claim your prize money now before it expires"),
    ("spam", "Nigerian prince needs your help to transfer millions. You get 20%"),
    ("spam", "Your Paypal account limited. Verify at paypa1-secure.com"),
    ("spam", "IRS tax refund pending. Enter SSN to receive"),
    ("spam", "Romance scam - send gift cards to continue chatting"),
    ("spam", "CEO urgent request: wire 50000 to vendor today"),
    ("spam", "Your package is held at customs. Pay fee to release"),
    ("spam", "Tech support: we detected virus. Call now to fix"),
    ("spam", "Phishing: your Netflix subscription expired. Update payment"),
    ("spam", "Suspicious login from Russia. Verify your identity"),
    ("spam", "You are eligible for government grant. Apply now"),
    ("spam", "Work from home. Earn 5000 weekly. No experience needed"),
    ("spam", "Medication at 90% off. Order now at fake-pharma.com"),
    ("spam", "Your crypto wallet compromised. Transfer funds immediately"),
    ("spam", "U have won a lottery please contact to the bank"),
    ("spam", "You have won a lottery please contact the bank"),
    ("spam", "U won lottery contact bank to claim"),
    ("spam", "Lucky winner! Claim your free iPhone. Reply with address"),
    ("spam", "Urgent: your password expires. Reset now or lose access"),
    ("spam", "Invoice attached. Please wire payment within 24 hours"),
    ("spam", "Final notice: your account will be deleted. Act now"),
    ("spam", "You have unclaimed cryptocurrency. Verify wallet to receive"),
]

def train_naive_bayes(data):
    """Train multinomial Naive Bayes. Returns word log-probs and priors."""
    spam_docs = [tokenize(msg) for label, msg in data if label == "spam"]
    ham_docs = [tokenize(msg) for label, msg in data if label == "ham"]

    spam_count = len(spam_docs)
    ham_count = len(ham_docs)
    total = spam_count + ham_count

    log_prior_spam = math.log((spam_count + 1) / (total + 2))
    log_prior_ham = math.log((ham_count + 1) / (total + 2))

    spam_word_count = defaultdict(float)
    ham_word_count = defaultdict(float)
    spam_total = 0
    ham_total = 0

    for doc in spam_docs:
        for word in doc:
            spam_word_count[word] += 1
            spam_total += 1
    for doc in ham_docs:
        for word in doc:
            ham_word_count[word] += 1
            ham_total += 1

    vocab = set(spam_word_count.keys()) | set(ham_word_count.keys())
    V = len(vocab)
    alpha = 1.0  # Laplace smoothing

    log_prob_spam = {}
    log_prob_ham = {}
    for word in vocab:
        log_prob_spam[word] = math.log((spam_word_count[word] + alpha) / (spam_total + alpha * V))
        log_prob_ham[word] = math.log((ham_word_count[word] + alpha) / (ham_total + alpha * V))

    default_log_prob = math.log(alpha / (min(spam_total, ham_total) + alpha * V))
    return {
        "logPriorSpam": log_prior_spam,
        "logPriorHam": log_prior_ham,
        "logProbSpam": {k: v for k, v in log_prob_spam.items()},
        "logProbHam": {k: v for k, v in log_prob_ham.items()},
        "defaultLogProb": default_log_prob,
        "vocabSize": V,
    }

def main():
    print("Training Naive Bayes on spam/ham data...")
    model = train_naive_bayes(TRAINING_DATA)

    output_path = os.path.join(os.path.dirname(__file__), "Email Extension", "spam_model.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2)

    print(f"Model saved to {output_path}")

if __name__ == "__main__":
    main()
