<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Exceptions;

use Ratespecial\Logto\Services\UserResolver;
use RuntimeException;
use Throwable;

/**
 * Thrown by {@see UserResolver} when saving a Logto user hits a unique constraint
 * because a different user row already has the token's email.  Typically the existing row predates Logto
 * (null subject, with `logto.link-unclaimed-by-email` off) or belongs to another Logto subject.
 *
 * Host apps can customise the response with `$exceptions->render(fn (DuplicateUserEmailException $e) => ...)`.
 */
class DuplicateUserEmailException extends RuntimeException
{
    public function __construct(
        public readonly string $subject,
        public readonly string $email,
        public readonly int|string $existingUserKey,
        public readonly bool $existingUserUnclaimed,
        ?Throwable $previous = null,
    ) {
        $message = "Logto subject {$subject} cannot be saved: user {$existingUserKey} already has email {$email}";
        if ($existingUserUnclaimed) {
            $message .= '; enable logto.link-unclaimed-by-email to link it';
        }

        parent::__construct($message, 0, $previous);
    }

    /**
     * @return array<string, mixed>
     */
    public function context(): array
    {
        return [
            'subject'                 => $this->subject,
            'email'                   => $this->email,
            'existing_user_key'       => $this->existingUserKey,
            'existing_user_unclaimed' => $this->existingUserUnclaimed,
        ];
    }
}
