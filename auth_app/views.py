'''this all modules are imported to use their functions.'''
import hashlib
from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from Crypto.Cipher import AES
from django.contrib.auth.decorators import login_required
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .forms import LoginForm, RegisterForm, SetPasswordForm
from django.template.loader import render_to_string
from .token import account_activation_token
from django.core.mail import EmailMessage


key = "wersdtfgyhbnjk"


def pad(data):
    ''' it is used in encrypt function'''
    # Create padding length
    length = 16 - (len(data) % 16)
    # Adding padding length to the data
    data += bytes([length]) * length
    return data


def encrypt(plain_text, key):
    ''' encrypt function for encrypting the user's data '''
    iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    enc_digest = hashlib.md5(key.encode('utf-8'))
    enc_cipher = AES.new(enc_digest.digest(), AES.MODE_CBC, iv)
    # Converting the data into byte code
    plain_text = pad(plain_text.encode('utf-8'))
    # Converting the data into hexadecimal
    encrypted_text = enc_cipher.encrypt(plain_text).hex()
    return encrypted_text


def unpad(text):
    ''' it is used in decrypt function'''
    # Get the last byte, which indicates the padding length
    padding_length = text[-1]
    # Remove the padding bytes
    return text[:-padding_length]


def decrypt(cipher_text, key):
    ''' decrypt function for decrypting the encrypted data '''
    iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    dec_digest = hashlib.md5(key.encode('utf-8'))
    dec_cipher = AES.new(dec_digest.digest(), AES.MODE_CBC, iv)
    encrypted_text = bytes.fromhex(cipher_text)
    # Decrypt the data
    decrypted_text = dec_cipher.decrypt(encrypted_text)
    # Converting the data into plain text
    result_text = unpad(decrypted_text).decode('utf-8')
    return result_text

def send_email_to_client(email):
    '''function declaring the send_mail function variables  '''
    subject = "You have successfully registered "
    message = " this is a test messgae from server"
    from_email=settings.EMAIL_HOST_USER
    recipient_list =[email]
    send_mail(subject=subject,message=message,from_email=from_email,recipient_list=recipient_list)


def register_view(request):
    '''register function which authenticate the user action and details.'''
    if request.method == 'GET':
        form = RegisterForm()
        return render(request, 'auth/register.html', {'form': form})
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            email = user.email
            username = encrypt(user.username, key)
            mail = encrypt(user.email, key)
            firstname = encrypt(user.first_name, key)
            lastname = encrypt(user.last_name, key)
            user.first_name = firstname
            user.last_name = lastname
            user.email = mail
            user.username = username

            user.save()
            activateEmail(request, user, form.cleaned_data.get('email'))
            messages.success(request, 'You have register successfully.')
            send_email_to_client(email)
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return redirect('login')
        else:
            for error in list(form.errors.values()):
                messages.error(request, error)

    else:
        form = UserRegistrationForm()
        # 
        # return redirect('login')
    return render(
        request=request, template_name="auth/register.html", context={"form": form})


def activateEmail(request, user, to_email):
    mail_subject = 'Activate your user account.'
    message = render_to_string('auth/template_activate_account.html', {
        'user': decrypt(user.username, key),
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        'protocol': 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        messages.success(request, f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
            received activation link to confirm and complete the registration. <b>Note:</b> Check your spam folder.')
    else:
        messages.error(
            request, f'Problem sending confirmation email to {to_email}, check if you typed it correctly.')


def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        messages.success(
            request, 'Thank you for your email confirmation. Now you can login your account.')
        return redirect('login')
    else:
        messages.error(request, 'Activation link is invalid!')
    return redirect('login')


def login_view(request):
    '''login function call when the user hit the login page .'''
    if request.method == 'GET':
        form = LoginForm()
        return render(request, 'auth/login.html', {'form': form})
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            use = username
            username = encrypt(use, key)
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                messages.success(request, f"Hi {use.title()}, welcome back!")
                return render(request, 'auth/home.html')
        # form is not valid or user is not authenticated
        messages.error(request, "Invalid username or password")
        return render(request, 'auth/login.html', {'form': form})
    return None


def logout_view(request):
    ''' logout view function'''
    logout(request)
    return redirect('login')


@login_required
def home_view(request):
    '''home function which will display the home page.'''
    return render(request, 'auth/home.html')


@login_required
def profile(request):
    ''' profile display view'''
    # decrypting the saved user details..
    if request.method == 'GET':
        user = User.objects.get(username=request.user)
        use = decrypt(user.username, key)
        mail = decrypt(user.email, key)
        fname = decrypt(user.first_name, key)
        lname = decrypt(user.last_name, key)
        return render(request, 'auth/profile.html', {'use': use,
                                                     'mail': mail,
                                                     'fname': fname,
                                                     'lname': lname})
    # User.objects.filter(username='username')
    if request.method == 'POST':
        user = User.objects.get(username=request.user)
        #  storing the updated user details
        username = request.POST.get('username')
        email = request.POST.get('email')
        firstname = request.POST.get('firstname')
        lastname = request.POST.get('lastname')
        #  encrypting the updated user details
        user.username = encrypt(username, key)
        user.email = encrypt(email, key)
        user.first_name = encrypt(firstname, key)
        user.last_name = encrypt(lastname, key)
        user.save()
        messages.success(request, 'Your details are updated successfully.')
        return redirect('profile')
    return render(request, 'auth/profile.html')


@login_required
def password_change(request):
    ''' password change function '''
    user = request.user
    if request.method == 'POST':
        form = SetPasswordForm(user, request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your password has been changed")
            return redirect('login')

    form = SetPasswordForm(user)
    return render(request, 'auth/password_change.html', {'form': form})