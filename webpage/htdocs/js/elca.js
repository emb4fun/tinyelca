
function Error2Text(err)
{
   switch(err) 
   {
      case  -3: msg = "The password does not meet the password policy requirements.";           break;
      case  -5: msg = "Incorrect password entered. Please try again.";                          break;
      case  -6: msg = "The encrypted keystore is currently still locked. Please unlock first."; break;
      case  -7: msg = "The key does not meet the policy requirements.";                         break;
      case  -8: msg = "Error, invalid CSR.";                                                    break;
      case  -9: msg = "Error, invalid certificate.";                                            break;
      default:  msg = "An internal error has occurred: " + err;                                 break;
   }   
   return(msg);
}
