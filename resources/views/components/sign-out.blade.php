{{--
    Sign-out form for the web sign-in flow: a CSRF-protected POST to the logto.sign-out route.
    Attributes go on the <form>. The slot replaces the default button.
--}}
<form method="POST" action="{{ route('logto.sign-out') }}" {{ $attributes }}>
    @csrf
    @if ($slot->isEmpty())
        <button type="submit">Sign out</button>
    @else
        {{ $slot }}
    @endif
</form>
