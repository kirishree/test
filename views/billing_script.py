from api.models import Subscription, FlavorPricing, SubscriptionInvoice, UserReachStack
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
import stripe
import logging
import time
import smtplib

stripe.api_key = settings.STRIPE_SECRET_KEY
logger = logging.getLogger('cloud')

from decouple import config
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

smtp_server = config('SMTP_SERVER')
smtp_port = config('SMTP_PORT')
sender_email = config('SENDER_MAIL_ID')
sender_password = config('SENDER_MAIL_PASSWORD')

MAX_RETRIES = 3  # Number of retry attempts for payment
RETRY_DELAY = 15  # Seconds delay between retries


def charge_customer(org, user_id, amount, invoice_id, subscription_id):
    return stripe.PaymentIntent.create(
        amount=int(amount * 100),
        currency="usd",
        customer=org.stripe_customer_id,
        payment_method=org.stripe_payment_method_id,
        off_session=True,
        confirm=True,
        metadata={
            "invoice_id": str(invoice_id),
            "user_id": str(user_id),
            "payable_amount": str(amount),
            "subscription_id": subscription_id
        }
    )


def post_mail(subject, message, recipient_list):
    for receiver_email in recipient_list:
        email_message = MIMEMultipart()
        email_message['From'] = sender_email
        email_message['To'] = receiver_email
        email_message['Subject'] = subject
        email_message.attach(MIMEText(message, 'plain'))

        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, email_message.as_string())
            server.quit()
            logger.info(f"Email sent successfully to {receiver_email}")
        except Exception as e:
            logger.error(f"Error sending email to {receiver_email}: {str(e)}")


def process_payment(org, user, invoice, subs):
    """
    Attempt payment with retry logic.
    """
    retry_count = 0

    while retry_count < MAX_RETRIES:
        try:
            logger.info(f"Attempting payment for {subs.resource_name}, try {retry_count + 1}")
            charge_customer(org, user.id, invoice.amount, invoice.invoice_number, subs.id)

            # Poll payment status
            for _ in range(10):
                invoice.refresh_from_db()

                if invoice.status == "paid":
                    logger.info(f"Payment successful for subscription {subs.resource_name}")
                    post_mail(
                        subject=f"ReachStack: Subscription Payment Successful - {subs.resource_name}",
                        message=f"Dear {user.username},\n\nYour payment for subscription {subs.resource_name} has been successfully processed.",
                        recipient_list=[user.email],
                    )
                    return True

                if invoice.status == "failed":
                    logger.warning(f"Payment failed status detected for {subs.resource_name}")
                    break

                time.sleep(5)

        except Exception as e:
            logger.error(f"Payment attempt {retry_count + 1} failed due to exception: {str(e)}")

        retry_count += 1
        logger.info(f"Retrying payment in {RETRY_DELAY} seconds...")
        time.sleep(RETRY_DELAY)

    # Final failure
    logger.error(f"All payment attempts failed for subscription {subs.resource_name}")
    post_mail(
        subject=f"ReachStack: Payment Failed - {subs.resource_name}",
        message=f"Dear {user.username},\n\nWe were unable to process your payment after {MAX_RETRIES} attempts. "
                f"Please update your payment method to avoid service interruption.",
        recipient_list=[user.email],
    )
    return False


def monthly_billing():
    todays_date = timezone.now().date()

    for subs in Subscription.objects.filter(status="active"):
        if subs.next_billing_date.date() == todays_date:
            org = subs.organization
            user = UserReachStack.objects.filter(organization=org, role="admin").first()
            flavorprice = FlavorPricing.objects.filter(flavor_id=subs.flavor_id).first()

            period_start = subs.next_billing_date
            period_end = period_start + timedelta(days=30)

            invoice = SubscriptionInvoice.objects.create(
                subscription=subs,
                amount=flavorprice.rate_monthly,
                start_period=period_start,
                end_period=period_end,
                status="unpaid",
            )

            invoice_number = f"INV-{timezone.now().year}-{invoice.id:04d}"
            invoice.invoice_number = invoice_number
            invoice.save(update_fields=["invoice_number"])

            logger.info(f"Invoice {invoice_number} generated for subscription {subs.resource_name}")

            payment_successful = process_payment(org, user, invoice, subs)

            # Update billing cycle only if payment succeeded
            if payment_successful:
                subs.next_billing_date = period_end
                subs.save(update_fields=['next_billing_date'])
                logger.info(f"Next billing date updated for {subs.resource_name}")
        else:
            print(f"The next billing date for subscription {subs.resource_name} is {subs.next_billing_date.date()}")
