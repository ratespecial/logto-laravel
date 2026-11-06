<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto\Support;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ratespecial\Logto\Support\Scopes;

class ScopesTest extends TestCase
{
    /**
     * @return array<string, array{mixed, list<string>}>
     */
    public static function cases(): array
    {
        return [
            'space-delimited string'  => ['user:read user:write', ['user:read', 'user:write']],
            'extra whitespace'        => ["  user:read \t user:write\n", ['user:read', 'user:write']],
            'duplicates in string'    => ['user:read user:write user:read', ['user:read', 'user:write']],
            'scope named zero kept'   => ['0 user:read', ['0', 'user:read']],
            'empty string'            => ['', []],
            'whitespace only'         => ['   ', []],
            'null'                    => [null, []],
            'array is not split'      => [['user:read', 'user:write'], ['user:read', 'user:write']],
            'array keys dropped'      => [[3 => 'user:read', 'x' => 'user:write'], ['user:read', 'user:write']],
            'array blanks and dupes'  => [['user:read', '', 'user:read'], ['user:read']],
            'array non-strings'       => [['user:read', 5, null, ['nested']], ['user:read']],
            'unsupported type'        => [42, []],
        ];
    }

    /**
     * @param  list<string>  $expected
     */
    #[DataProvider('cases')]
    public function testParse(mixed $input, array $expected): void
    {
        $this->assertSame($expected, Scopes::parse($input));
    }
}
