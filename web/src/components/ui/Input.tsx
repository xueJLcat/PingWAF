import { forwardRef, useId, type InputHTMLAttributes, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: ReactNode
  hint?: ReactNode
  error?: ReactNode
  prefixIcon?: ReactNode
  suffixIcon?: ReactNode
  containerClassName?: string
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      hint,
      error,
      prefixIcon,
      suffixIcon,
      containerClassName,
      className,
      id,
      required,
      ...props
    },
    ref,
  ) => {
    const generatedId = useId()
    const inputId = id ?? generatedId
    const describedBy = error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined

    return (
      <div className={cn('flex flex-col gap-1.5', containerClassName)}>
        {label && (
          <label
            htmlFor={inputId}
            className="text-[13px] font-medium text-fg-subtle"
          >
            {label}
            {required && <span className="ml-0.5 text-danger">*</span>}
          </label>
        )}
        <div className="relative flex items-center">
          {prefixIcon && (
            <span className="pointer-events-none absolute left-3 flex items-center text-fg-subtle [&>svg]:h-4 [&>svg]:w-4">
              {prefixIcon}
            </span>
          )}
          <input
            ref={ref}
            id={inputId}
            required={required}
            aria-invalid={error ? true : undefined}
            aria-describedby={describedBy}
            className={cn(
              'h-9 w-full rounded-md border bg-elevated text-sm text-fg placeholder:text-fg-subtle/60',
              'transition-[border-color,box-shadow] duration-150',
              'focus:border-focus focus:outline-none focus:ring-2 focus:ring-focus/25',
              'disabled:cursor-not-allowed disabled:opacity-60',
              error ? 'border-danger focus:border-danger focus:ring-danger/25' : 'border-line',
              prefixIcon ? 'pl-9' : 'pl-3',
              suffixIcon ? 'pr-9' : 'pr-3',
              props.type === 'file' && 'min-w-0 cursor-pointer truncate border-0 bg-transparent px-0 file:mr-3 file:h-9 file:cursor-pointer file:rounded-md file:border file:border-line file:bg-recessed file:px-3 file:text-sm file:font-medium file:text-fg hover:file:bg-elevated focus-visible:outline-2 focus-visible:outline-focus',
              className,
            )}
            {...props}
          />
          {suffixIcon && (
            <span className="absolute right-3 flex items-center text-fg-subtle [&>svg]:h-4 [&>svg]:w-4">
              {suffixIcon}
            </span>
          )}
        </div>
        {error ? (
          <p id={`${inputId}-error`} className="text-xs text-fg-danger">
            {error}
          </p>
        ) : hint ? (
          <p id={`${inputId}-hint`} className="text-xs text-fg-subtle">
            {hint}
          </p>
        ) : null}
      </div>
    )
  },
)

Input.displayName = 'Input'
