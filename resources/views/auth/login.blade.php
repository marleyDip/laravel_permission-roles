<style>
    .social-link {
        margin-right: 10px;
    }
    .social-link img {
        width: 30px;
    }
</style>

<x-guest-layout>
    <!-- Session Status -->
    <x-auth-session-status class="mb-4" :status="session('status')" />

    <form method="POST" action="{{ route('login') }}">
        @csrf

        <!-- Email Address -->
        <div>
            <x-input-label for="email" :value="__('Email')" />
            <x-text-input id="email" class="block mt-1 w-full" type="email" name="email" :value="old('email')" required autofocus autocomplete="username" />
            <x-input-error :messages="$errors->get('email')" class="mt-2" />
        </div>

        <!-- Password -->
        <div class="mt-4">
            <x-input-label for="password" :value="__('Password')" />

            <x-text-input id="password" class="block mt-1 w-full"
                            type="password"
                            name="password"
                            required autocomplete="current-password" />

            <x-input-error :messages="$errors->get('password')" class="mt-2" />
        </div>

        <!-- Remember Me -->
        <div class="block mt-4">
            <label for="remember_me" class="inline-flex items-center">
                <input id="remember_me" type="checkbox" class="rounded border-gray-300 text-indigo-600 shadow-sm focus:ring-indigo-500" name="remember">
                <span class="ms-2 text-sm text-gray-600">{{ __('Remember me') }}</span>
            </label>
        </div>

        <div class="flex items-center justify-between mt-4">

            @if (Route::has('password.request'))
                <a class="underline text-sm text-gray-600 hover:text-gray-900 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500" href="{{ route('password.request') }}">
                    {{ __('Forgot your password?') }}
                </a>
            @endif

            <x-primary-button class="ms-3">
                {{ __('Log in') }}
            </x-primary-button>
        </div>

        {{-- Social Media Login Section --}}
        <div class="flex items-center mt-4">

            {{-- Login with Google --}}
            <a title="Login with Google" href="{{ route('auth.redirection', 'google') }}" class="social-link inline-block px-3 py-2 rounded-lg shadow">
                <img src="{{ asset('build/assets/icons/google.png') }}" alt="" />
            </a>

            {{-- Login with Facebook --}}
            <a title="Login with Facebook" href="{{ route('auth.redirection', 'facebook') }}" class="social-link inline-block px-3 py-2 rounded-lg shadow">
                <img src="{{ asset('build/assets/icons/facebook.jpeg') }}" alt="" />
            </a>

            {{-- Login with Github --}}
            <a title="Login with Github" href="{{ route('auth.redirection', 'github') }}" class="social-link inline-block px-3 py-2 rounded-lg shadow">
                <img src="{{ asset('build/assets/icons/github.png') }}" alt="" />
            </a>

            {{-- Login with LinkedIn --}}
            <a title="Login with LinkedIn" href="{{ route('auth.redirection', 'linkedin-openid') }}" class="social-link inline-block px-3 py-2 rounded-lg shadow">
                <img src="{{ asset('build/assets/icons/linkedin.jpeg') }}" alt="" />
            </a>

        </div>
    </form>
</x-guest-layout>
