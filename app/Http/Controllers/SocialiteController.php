<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;

class SocialiteController extends Controller
{
    /**
     * Function: authProviderRedirect
     * Description: This Function Will Redirect to Given provider
     * @paramNA
     * @returnvoid
     */
    public function authProviderRedirect($provider){
        if ($provider){
            return Socialite::driver($provider)->redirect();
        }
        abort(404);
    }

    /**
     * Function: googleAuthentication
     * Description: This Function Will Authenticate the user through the Google Account
     * @paramNA
     * @returnvoid
     */

    public function socialAuthentication($provider){

        try {

            if ($provider){
                $socialUser = Socialite::driver($provider)->user();

                // Check if user exists by auth_provider_id
                $user = User::where('auth_provider_id', $socialUser->id)->first();

                if ($user) {

                    // Log the user in
                    Auth::login($user);

                } else {

                    // Check if a user with the same email exists
                    $existingUser = User::where('email', $socialUser->email)->first();

                    if ($existingUser) {

                        // Update the auth_provider_id and provider if needed
                        $existingUser->update([
                            'auth_provider_id' => $socialUser->id,
                            'auth_provider' => $provider,
                        ]);

                        // Log the user in
                        Auth::login($existingUser);

                    } else {

                        // Create a new user
                        $userData = User::create([
                            'name' => $socialUser->name,
                            'email' => $socialUser->email,
                            'password' => Hash::make('12345678'), // Default password
                            'auth_provider_id' => $socialUser->id,
                            'auth_provider' => $provider,
                        ]);

                        // Log the new user in
                        if ($userData) {
                            Auth::login($userData);
                        }
                    }
                }

                return redirect()->route('dashboard');
            }

            abort(404);

        } catch (Exception $e){

            // dd($e);  For debugging purposes, you can replace this with logging

            //Use \Log::error to save error details in storage/logs/laravel.log.
            Log::error('Social authentication error:', [
                'provider' => $provider,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            // Optionally redirect to an error page or display a flash message
            return redirect()->route('login')
                ->with('error', 'Something went wrong during social authentication. Please try again.');
        }
    }
}
