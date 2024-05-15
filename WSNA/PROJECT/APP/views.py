from django.shortcuts import render, redirect
from . models import UserPersonalModel
from . forms import UserPersonalForm, UserRegisterForm
from django.contrib.auth import authenticate, login,logout
from django.contrib import messages
import numpy as np
import joblib


def Landing_1(request):
    return render(request, '1_Landing.html')

def Register_2(request):
    form = UserRegisterForm()
    if request.method =='POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            user = form.cleaned_data.get('username')
            messages.success(request, 'Account was successfully created. ' + user)
            return redirect('Login_3')

    context = {'form':form}
    return render(request, '2_Register.html', context)


def Login_3(request):
    if request.method =='POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('Home_4')
        else:
            messages.info(request, 'Username OR Password incorrect')

    context = {}
    return render(request,'3_Login.html', context)

def Home_4(request):
    return render(request, '4_Home.html')

def Teamates_5(request):
    return render(request,'5_Teamates.html')

def Domain_Result_6(request):
    return render(request,'6_Domain_Result.html')

def Problem_Statement_7(request):
    return render(request,'7_Problem_Statement.html')
    

def Per_Info_8(request):
    if request.method == 'POST':
        fieldss = ['firstname','lastname','age','address','phone','city','state','country']
        form = UserPersonalForm(request.POST)
        if form.is_valid():
            print('Saving data in Form')
            form.save()
        return render(request, '4_Home.html', {'form':form})
    else:
        print('Else working')
        form = UserPersonalForm(request.POST)    
        return render(request, '8_Per_Info.html', {'form':form})
    
Model = joblib.load('C:/Users/DHARUN/Music/MAIN_PROJECT/CODE/PROJECT/APP/MODEL.pkl')

    
def Deploy_9(request): 
    if request.method == "POST":
        int_features = [x for x in request.POST.values()]
        int_features = int_features[1:]
        print(int_features)
        final_features = [np.array(int_features, dtype=object)]
        print(final_features)
        prediction = Model.predict(final_features)
        print(prediction)
        output = prediction[0]
        print(f'output{output}')
        if output == 0:
            c = "THE BLACKHOLE ATTACK MIGHT BE OCCUR IN THIS CONDITIONS"
            a = "PREVENTION : Use secure and encrypted communication protocols.Implement intrusion detection systems to identify unusual network behavior.Employ packet filtering to block suspicious or malicious traffic."
            b = "PRECAUTION : Regularly update and patch software to address vulnerabilities.Educate users about phishing and social engineering tactics to prevent unauthorized access."
        elif output == 1:
            c = "THE FLOODING ATTACK MIGHT BE OCCUR IN THIS CONDITIONS"
            a = "PREVENTION : Implement robust firewall rules to filter and block suspicious incoming traffic.Utilize rate limiting mechanisms to restrict the number of requests from a single source.Deploy intrusion prevention systems to detect and block flood-like patterns."
            b = "PRECAUTION : Employ Content Delivery Networks (CDNs) to distribute and absorb traffic.Regularly update and patch software to address vulnerabilities exploited in flooding attacks."
        elif output == 2:
            c = "THE GRAYHOLE ATTACK MIGHT BE OCCUR IN THIS CONDITIONS"
            a = "PREVENTION : Implement robust network firewalls.Regularly update and patch software vulnerabilities.Employ intrusion detection and prevention systems."
            b = "PRECAUTION : Educate users on phishing and social engineering risks.Monitor network traffic for unusual patterns and behaviors."
        elif output == 3:
            c = "THE NONE OF ATTACK MIGHT BE OCCUR IN THIS CONDITIONS. THIS IS NORMAL"
            a = "PREVENTION : NO NEED PREVENTION"
            b = "PRECAUTION : NO NEED PREVENTION"
        else:
            c = "THE TIME DIVISION MULTIPLE ACCESS ATTACK MIGHT BE OCCUR IN THIS CONDITIONS"
            a = "PREVENTION : Implement strong authentication measures for Time Division Multiple Access (TDMA) networks.Employ encryption protocols to secure TDMA communications.Regularly update and patch TDMA network devices to address vulnerabilities."
            b = "PRECAUTION : Monitor network traffic for unusual patterns or anomalies.Educate users on security best practices to prevent social engineering attacks on TDMA systems."
        return render(request, '9_Deploy.html', {"c":c,"b": b, "a":a})
    else:
        return render(request, '9_Deploy.html')


def Per_Database_10(request):
    models = UserPersonalModel.objects.all()
    return render(request, '10_Per_Database.html', {'models':models})

def Logout(request):
    logout(request)
    return redirect('Landing_1')
